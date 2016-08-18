# --------------------------------------------------------------------------- #

import logging


from libcloud.dns import providers
from libcloud.dns.types import RecordType

from asyncme.challenges import DNS01ChallengeHandler


# --------------------------------------------------------------------------- #

# Typing Imports

from typing import Union

from libcloud.dns import base


# --------------------------------------------------------------------------- #


LOG = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #


class LibcloudHandler(DNS01ChallengeHandler):

    def __init__(self, *args, provider: str, credentials: tuple, **kwargs):
        super().__init__(*args, **kwargs)

        driver_cls = providers.get_driver(provider.lower())
        self.driver = driver_cls(*credentials)

    @staticmethod
    def __find_record_in_zone(name: str,
                              zone: base.Zone) -> Union[base.Record, None]:
        try:
            return next(r for r in zone.list_records() if r.name == name)
        except StopIteration:
            return None

    def __find_zone(self) -> base.Zone:

        zone_parts = self.txt_record_name().split(".")

        for i in range(len(zone_parts) - 2):
            zone_name = '.'.join(zone_parts[i:])

            try:
                zone = next(z for z in self.driver.list_zones()
                            if z.domain.rstrip('.') == zone_name.rstrip('.'))
                break
            except StopIteration:
                pass

        else:
            raise RuntimeError("No Suitable Zone for {} was Found".format(
                self.txt_record_name()
            ))

        return zone

    async def _do_cleanup(self):

        # The Libcloud work must be done in an executor since it
        # blocks.
        def work():

            # (1) Find the Zone corresponding to the FQDN and Record Name
            zone = self.__find_zone()

            LOG.debug("Found Zone: {}".format(zone))

            zone_parts = zone.domain.rstrip('.').split('.')
            rec_parts = self.txt_record_name().split('.')

            rec_name = '.'.join(rec_parts[:-len(zone_parts)])

            LOG.debug("Looking for Record: {}".format(rec_name))

            # (2) Cleanup and Records Found
            record = self.__find_record_in_zone(rec_name, zone)

            if record:
                record.delete()

        await self._loop.run_in_executor(None, work)

    async def _do_perform(self):

        # The Libcloud work must be done in an executor since it
        # blocks.
        def work():

            # (1) Find the Zone corresponding to the FQDN and Record Name
            zone = self.__find_zone()

            LOG.debug("Found Zone: {}".format(zone))

            zone_parts = zone.domain.rstrip('.').split('.')
            rec_parts = self.txt_record_name().split('.')

            rec_name = '.'.join(rec_parts[:-len(zone_parts)])

            # (2) Add the new TXT Record with the Challenge Contents
            record = self.__find_record_in_zone(rec_name, zone)

            if record:
                record.delete()

            LOG.debug("Adding Record: {}".format(rec_name))

            zone.create_record(
                name=rec_name,
                type=RecordType.TXT,
                data='"{}"'.format(self.txt_record_contents())
            )

        await self._loop.run_in_executor(None, work)
