from honeybadger import db, logger
from honeybadger.models import Beacon
from honeybadger.parsers import parse_airport, parse_netsh, parse_iwlist, parse_google
from honeybadger.plugins import get_coords_from_google, get_coords_from_ipstack, get_coords_from_ipinfo
from base64 import b64decode as b64d
import re

def add_beacon(*args, **kwargs):
    b = Beacon(**kwargs)
    db.session.add(b)
    db.session.commit()
    logger.info(
        f"Target location identified as Lat: {kwargs['lat']}, Lng: {kwargs['lng']}"
    )

def process_json(data, jsondata):
    logger.info('Processing JSON data.')
    logger.info(f'Data received:\n{jsondata}')
    # process Google device data
    if jsondata.get('scan_results'):
        if aps := parse_google(jsondata['scan_results']):
            logger.info(f'Parsed access points: {aps}')
            coords = get_coords_from_google(aps)
            if all(list(coords.values())):
                add_beacon(
                    target_guid=data['target'],
                    agent=data['agent'],
                    ip=data['ip'],
                    port=data['port'],
                    useragent=data['useragent'],
                    comment=data['comment'],
                    lat=coords['lat'],
                    lng=coords['lng'],
                    acc=coords['acc'],
                )
                return True
            else:
                logger.error('Invalid coordinates data.')
        else:
            # handle empty data
            logger.info('No AP data received.')
    else:
        # handle unrecognized data
        logger.info('Unrecognized data received from the agent.')

def process_known_coords(data):
    logger.info('Processing known coordinates.')
    add_beacon(
        target_guid=data['target'],
        agent=data['agent'],
        ip=data['ip'],
        port=data['port'],
        useragent=data['useragent'],
        comment=data['comment'],
        lat=data['lat'],
        lng=data['lng'],
        acc=data['acc'],
    )
    return True

def process_wlan_survey(data):
    logger.info('Processing wireless survey data.')
    os = data['os']
    _data = data['data']
    content = b64d(_data).decode()
    logger.info(f'Data received:\n{_data}')
    logger.info(f'Decoded Data:\n{content}')
    if _data:
        aps = []
        if re.search('^mac os x', os.lower()):
            aps = parse_airport(content)
        elif re.search('^windows', os.lower()):
            aps = parse_netsh(content)
        elif re.search('^linux', os.lower()):
            aps = parse_iwlist(content)
        # handle recognized data
        if aps:
            logger.info(f'Parsed access points: {aps}')
            coords = get_coords_from_google(aps)
            if all(list(coords.values())):
                add_beacon(
                    target_guid=data['target'],
                    agent=data['agent'],
                    ip=data['ip'],
                    port=data['port'],
                    useragent=data['useragent'],
                    comment=data['comment'],
                    lat=coords['lat'],
                    lng=coords['lng'],
                    acc=coords['acc'],
                )
                return True
            else:
                logger.error('Invalid coordinates data.')
        else:
            # handle unrecognized data
            logger.info('No parsable WLAN data received.')
    else:
        # handle blank data
        logger.info('No data received from the agent.')
    return False

def process_ip(data):
    logger.info('Processing IP address.')
    coords = get_coords_from_ipstack(data['ip'])
    if not all(list(coords.values())):
        # No data. try again with the fallback.
        logger.info('Using fallback API.')
        coords = get_coords_from_ipinfo(data['ip'])

    if all(list(coords.values())):
        add_beacon(
            target_guid=data['target'],
            agent=data['agent'],
            ip=data['ip'],
            port=data['port'],
            useragent=data['useragent'],
            comment=data['comment'],
            lat=coords['lat'],
            lng=coords['lng'],
            acc='Unknown',
        )
        return True
    else:
        logger.error('Invalid coordinates data.')
    return False
