# --------------------------------------------------------------------------- #


from enum import Enum
import hashlib
import logging
import time

from arroyo import utils
from dns.resolver import get_default_resolver, NoAnswer, NXDOMAIN


# --------------------------------------------------------------------------- #

# Typing Imports

import asyncio

from acme import messages


# --------------------------------------------------------------------------- #


LOG = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #


class ChallengeType(str, Enum):
    DNS_01 = 'dns-01',
    HTTP_01 = 'http-01',
    TLS_SNI_01 = 'tls-sni-01'


class ChallengeFailure(RuntimeError):
    pass


class AcmeChallenge:
    """
    An ACME challenge, used to authorize a client for a specific identifier,
    e.g. domain name.

    Typically you do not instantiate this yourself, but call
    ``get_domain_challenges`` on the ``AsyncmeClient``.
    """

    def __init__(self, challenge: messages.ChallengeBody,
                 acme_client: "asyncme.client.ExecutorClient"):
        """
        Initializes the new AcmeChallenge

        :param challenge: Underlying ACME challenge message.
        :param acme_client: Underlying ACME client.
        """

        # The underlying key must be passed in, in order to generate
        # the key authorization. It is passed in through the client.

        self._challb = challenge
        self._client = acme_client

    @property
    def key_authorization(self) -> str:
        """
        Returns the key authorization for this challenge.
        """
        return self._challb.chall.key_authorization(self._client.key)

    @property
    def status(self):
        return self._challb.status

    @property
    def type(self) -> ChallengeType:
        """
        Returns this challenge's type.
        """
        return ChallengeType(self._challb.chall.typ)

    @property
    def uri(self) -> str:
        """
        Returns the URI to this challenge's resource on the ACME server.
        """
        return self._challb.uri

    async def answer(self) -> None:
        """
        Answer the challenge, asking the server to check for the result.
        """
        resp = self._challb.chall.response(self._client.key)
        updated = await self._client.answer_challenge(self._challb, resp)
        self._challb = updated.body


# --------------------------------------------------------------------------- #


class AcmeChallengeHandler:
    """
    An ``AcmeChallengeHandler`` is used to fulfill a specific ACME challenge.
    The challenge handler may be used by calling the ``perform`` method.

    Subclasses can be implemented to automatically fulfill challenges
    automatically. To do this, they must define the following methods:

    :``_do_cleanup``: Perform handler cleanup.
    :``_do_perform``: Setup of the challenge requirements.

    In addition, handlers may define:

    :``_do_verify``: Verification of the challenge setup, used to verify that
     the server is ready to attempt validating the answer.

    :cvar type: The challenge type this handler fulfills.

    :ivar challenge: The ``AcmeChallenge`` this handler is performing against.
    :ivar domain: The domain being challenged.
    """

    type = None                                     # type: ChallengeType

    def __init__(self, challenge: AcmeChallenge, domain: str, *,
                 loop: asyncio.AbstractEventLoop = None):
        """
        Creates a new handler for an AcmeChallenge.

        :param challenge: The instance of ``AcmeChallenge`` this handler
         will perform upon.
        :param loop: Loop used to perform any challenge configuration.
        """

        if not self.type or self.type not in ChallengeType:
            raise ValueError("This handler does not have a valid type set")

        if self.type != challenge.type:
            raise ValueError("This handler handles "
                             "{}, not {}".format(self.type, challenge.type))

        self.challenge = challenge
        self.domain = domain
        self._loop = loop or asyncio.get_event_loop()

    async def _do_cleanup(self) -> None:
        pass                                                                    # pragma: nocover # noqa

    async def _do_perform(self) -> None:
        pass                                                                    # pragma: nocover # noqa

    async def _do_verify(self) -> None:
        pass                                                                    # pragma: nocover # noqa

    async def perform(self) -> None:
        """
        Performs the challenge.

        :raises ChallengeFailure: If the challenge fails or otherwise cannot be
         completed.
        """
        try:
            LOG.debug("Calling Handler Perform")
            await self._do_perform()
            LOG.debug("Calling Handler Verify")
            await self._do_verify()
            LOG.debug("Calling Challenge Answer")
            await self.challenge.answer()
        except Exception as e:
            raise ChallengeFailure() from e
        finally:
            await self._do_cleanup()


class DNS01ChallengeHandler(AcmeChallengeHandler):
    """
    An ``AcmeChallengeHandler`` used to handle `DNS-01` challenges.

    .. note::

        This class does not perform automatic handling of DNS records,
        and requires a subclass to perform such automation.

        Do not use this class directly unless you plan to manually
        perform the challenge.


    Subclasses must still implement:

    :``_do_cleanup``: Perform handler cleanup.
    :``_do_perform``: Setup of the challenge requirements.

    An implementation of ``_do_verify`` is provided.
    """

    type = ChallengeType.DNS_01

    def _wait_for_txt_record(self, nameserver: str,
                             min_hits: int = 2, attempts: int = 12) -> None:

        # This method is expected to be run in an executor.

        domain = self.txt_record_name()
        hits = 0

        LOG.info(
            "Waiting for TXT Record {}: {} Attempts".format(domain, attempts)
        )

        for i in range(attempts):

            time.sleep(5)

            # (1) Query for the DNS Record (Answer)
            resolver = get_default_resolver()
            resolver.nameservers = [nameserver, ]

            try:
                query = resolver.query(domain, 'TXT')
                answers = query.response.answer
            except (NoAnswer, NXDOMAIN):
                LOG.debug("TXT Record {} Not Found: Attempt {}/{}".format(
                    domain, i + 1, attempts
                ))
                continue

            # (2) Check Answer Content
            for a in answers:
                if any(self.txt_record_contents() in str(r) for r in a.items):
                    LOG.debug("Valid TXT Record {} Found on Attempt {}".format(
                        domain, i + 1
                    ))

                    hits += 1

                    LOG.debug("Number of Hits: {}/{}".format(hits, min_hits))
                    if hits >= min_hits:
                        return  # Minimum Number of Hits Found

                else:
                    LOG.debug(
                        "Invalid TXT Record {} Found on "
                        "Attempt {}/{}".format(domain, i + 1, attempts)
                    )

        else:
            if not hits:
                msg = "Failed to Find Valid Record for {}".format(domain)
                LOG.error(msg)
                raise ChallengeFailure(msg)
            else:
                msg = "Record {} Only Found {} Times But Required {}".format(
                    domain, hits, min_hits
                )
                LOG.error(msg)
                raise ChallengeFailure(msg)

    async def _do_verify(self) -> None:
        """
        Performs DNS verification to ensure that DNS records have been
        sufficiently propagated before answering the remote ACME server.

        :raises ChallengeFailure: If propagation could not be verified.
        """
        await self._loop.run_in_executor(
            None,
            self._wait_for_txt_record, '8.8.8.8', 8, 120
        )
        await self._loop.run_in_executor(
            None,
            self._wait_for_txt_record, '8.8.4.4', 4, 60
        )

    def txt_record_contents(self) -> str:
        """
        :return: Expected contents of the DNS TEXT record used to satisfy
         this DNS-01 challenge.
        """
        checksum = hashlib.sha256()
        checksum.update(self.challenge.key_authorization.encode())
        return utils.jose_b64encode(checksum.digest())

    def txt_record_name(self) -> str:
        """
        :return: The name of the DNS TXT record used to satisfy this DNS-01
         challenge.
        """
        return '_acme-challenge.' + self.domain
