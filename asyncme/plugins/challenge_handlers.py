
import asyncio
import logging

from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes

from dns.resolver import query, NoAnswer, NXDOMAIN

from asyncme import utils
from asyncme.acme.challenges import AcmeChallengeType, AcmeChallenge


# --------------------------------------------------------------------------- #


LOG = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #


class ChallengeFailure(RuntimeError):
    pass


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

    :ivar type: The challenge type this handler fulfills.
    """

    type = None                                     # type: AcmeChallengeType

    def __init__(self, challenge: AcmeChallenge, *,
                 loop: asyncio.BaseEventLoop = None):
        """
        Creates a new handler for an AcmeChallenge.

        :param challenge: The instance of ``AcmeChallenge`` this handler
         will perform and answer.
        :param loop: Loop used to perform any challenge configuration. If
         not set, the loop will be inferred from the ``AcmeChallenge``.
        """

        if not isinstance(challenge, AcmeChallenge):
            raise TypeError("`challenge` must be an instance of {}".format(
                AcmeChallenge
            ))

        if not self.type or self.type not in AcmeChallengeType:
            raise ValueError("This handler does not have a valid type set")

        if self.type != challenge.type:
            raise ValueError("This handler handles "
                             "{}, not {}".format(self.type, challenge.type))

        self.challenge = challenge
        self.__loop = loop or self.challenge.get_client_loop()

    def __str__(self):
        return "{} Handler ({})".format(self.type, self.challenge.fqdn).upper()

    @property
    def loop(self) -> asyncio.BaseEventLoop:
        """
        :return: The asynchronous loop used by this handler.
        """
        return self.__loop

    async def _do_cleanup(self) -> None:
        raise RuntimeError("Must be overridden by the handler subclass")        # pragma: nocover # noqa

    async def _do_perform(self) -> None:
        raise RuntimeError("Must be overridden by the handler subclass")        # pragma: nocover # noqa

    async def _do_verify(self) -> None:
        return                                                                  # pragma: nocover # noqa

    async def perform(self) -> None:
        """
        Performs the challenge.

        :raises ChallengeFailure: If the challenge fails or otherwise cannot be
         completed.
        """
        try:
            await self._do_perform()
            await self._do_verify()
            await self.challenge.answer()

            # Wait for Authorization Status Change (Max 60 seconds)
            for _ in range(12):

                status = await self.challenge.get_status()
                if status != 'valid':

                    if status in ('invalid', 'revoked'):
                        msg = ("Remote server was not satisfied with "
                               "challenge: {}".format(status))
                        LOG.warn("{}: {}".format(self, msg))

                        raise ChallengeFailure(msg)

                    LOG.info("Waiting 5 Seconds before Rechecking Authz "
                             "Status")
                    await asyncio.sleep(5)

                else:
                    break

        except ChallengeFailure:
            raise
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

    type = AcmeChallengeType.DNS_01

    async def _do_verify(self) -> None:
        """
        Performs DNS verification to ensure that DNS records have been
        sufficiently propagated before answering the remote ACME server.

        Verification uses 12x 5s intervals, taking a max of 60 seconds.

        :raises ChallengeFailure: If propagation could not be verified.
        """

        # XXX: The calls to the DNS resolver probably block and may not be
        # XXX: async safe. Consider moving to an executor.

        LOG.debug("{}: _do_verify called".format(self))

        for _ in range(12):

            await asyncio.sleep(5)

            # (1) Query for the DNS Record (Answer)
            LOG.debug("{}: _do_verify querying for "
                      "{}".format(self, self.txt_record_name()))
            try:
                answers = query(self.txt_record_name(), 'TXT').response.answer
            except (NoAnswer, NXDOMAIN):
                LOG.debug("{}: _do_verify no records found".format(self))
                continue

            # (2) Check Answer Content
            for a in answers:
                if any(self.txt_record_contents() in str(r) for r in a.items):
                    LOG.debug("{}: _do_verify success".format(self))
                    return  # Found Valid TXT Record!
                else:
                    LOG.debug("{}: _do_verify record found but with wrong "
                              "contents".format(self))

        else:
            LOG.error("{}: Failed to Verify DNS Propagation".format(self))
            raise ChallengeFailure("Failed to Verify DNS Propagation")

    def txt_record_contents(self) -> str:
        """
        :return: Expected contents of the DNS TEXT record used to satisfy
         this DNS-01 challenge.
        """
        digest = hashes.Hash(hashes.SHA256(), backends.default_backend())
        digest.update(self.challenge.key_authorization.encode())
        return utils.jose_b64encode(digest.finalize())

    def txt_record_name(self) -> str:
        """
        :return: The name of the DNS TXT record used to satisfy this DNS-01
         challenge.
        """
        return '_acme-challenge.' + self.challenge.fqdn


# class HTTP01ChallengeHandler(AcmeChallengeHandler):
#     """
#     NOT YET IMPLEMENTED
#     """
#
#     type = AcmeChallengeType.HTTP_01
#
#
# class TLSSNI01ChallengeHandler(AcmeChallengeHandler):
#     """"
#     NOT YET IMPLEMENTED
#     """
#
#     type = AcmeChallengeType.TLS_SNI_01
