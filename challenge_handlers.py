
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes

from asyncme import utils
from asyncme.acme.challenges import AcmeChallengeHandler, AcmeChallengeType


# --------------------------------------------------------------------------- #


class LibCloudDNSHandler(AcmeChallengeHandler):
    """
    This class handles 'dns-01' ACME challenges via Apache's LibCloud.
    To use this handler ensure that LibCloud is installed:

    .. code::
        $ pip install apache-libcloud

    """

    type = AcmeChallengeType.DNS_01

    async def perform(self, provider, credentials):
        """
        Perform the challenge using Apache's LibCloud.

        :param provider: The libcloud DNS provider
         ``libcloud.dns.providers.Provider``
        :param credentials: The credentials for the libcloud DNS provider, as
         a tuple. The credentials will be passed directly into the provider's
         driver class.

        :raises RuntimeError: If a suitable zone for the domain to authorize
         could not be found.
        """

        from libcloud.dns.providers import get_driver
        from libcloud.dns.types import RecordType

        # STEP 1:   Get and Normalize the FQDN to be Authorized
        fqdn = (await self.get_authz())['identifier']['value']
        if not fqdn.endswith("."):
            fqdn += "."

        # Perform the rest of the steps in an executor since
        # LibCloud blocks.

        def do_libcloud_work():

            # STEP 2:   Load the Libcloud Driver and the Corresponding Zone

            cls = get_driver(provider)
            driver = cls(*credentials)

            # We loop through each part of the domain to see if we can find
            # the most specific zone to apply.
            zone_parts = fqdn.split(".")

            for i in range(len(zone_parts) - 2):
                zone_name = ".".join(zone_parts[i:])
                record_name = '_acme-challenge.' + '.'.join(zone_parts[:i])

                try:
                    zone = next(z for z in driver.list_zones()
                                if z.domain == zone_name)
                    break
                except StopIteration:
                    pass

            else:
                raise RuntimeError("Unable to find a suitable zone for "
                                   "{}".format(fqdn))

            # STEP 3:   Add the new TXT Record with the Challenge Contents
            # Clean up Record Name
            if record_name.endswith("."):
                record_name = record_name.rstrip(".")

            # TXT Record contents is the JOSE Base64 encoding of the SHA256
            # digest of the keyAuthorization.
            digest = hashes.Hash(hashes.SHA256(), backends.default_backend())
            digest.update(self.key_authorization.encode())
            txt_data = utils.jose_b64encode(digest.finalize())

            # Check if the Record already Exists
            try:
                record = next(r for r in zone.list_records()
                              if r.name == record_name)
                record.update(data='"{}"'.format(txt_data))

            except StopIteration:
                zone.create_record(
                    name=record_name,
                    type=RecordType.TXT,
                    data='"{}"'.format(txt_data)
                )

        # RUN IN EXECUTOR
        await self.loop.run_in_executor(None, do_libcloud_work)
