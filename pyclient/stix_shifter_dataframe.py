import json
import time
import logging
import pandas as pd
from anytree import Node, PreOrderIter
from pandas import json_normalize
from stix_shifter.stix_translation import stix_translation
from stix_shifter.stix_transmission import stix_transmission


class StixShifterDataFrame(object):
    def __init__(self):
        self.configs = {}


    def add_config(self, config_name: str, config_content: dict):
        if 'connection' not in config_content or 'configuration' not in config_content:
            raise Exception('connection and configuration should be in config.')

        # TODO: add protect mechanism in case any accidental overwrite.
        self.configs.update({config_name: config_content})


    def stix_shiter_execute(self, config_name: str, stix_query: str):
        # Execute means take the STIX SCO pattern as input, execute query, and return STIX as output
        # ref: https://github.com/opencybersecurityalliance/stix-shifter/blob/ee4bdf754fc9c2a80cb5b5607210e53dd2657b72/stix_shifter/scripts/stix_shifter.py#L251
        # TODO: wrapper stix-shifter's cml tool to be function to replace this method.
        config = self.configs[config_name]

        connection_dict, configuration_dict = config['connection'], config['configuration'],
        translation_module, transmission_module, data_source = config_name, config_name, {}
        options = {}

        if 'options' in connection_dict:
            options.update(connection_dict['options'])
        options['validate_pattern'] = True

        translation = stix_translation.StixTranslation()
        dsl = translation.translate(translation_module, 'query', data_source, stix_query, options)
        logging.debug('Translated Queries: ' + json.dumps(dsl))

        transmission = stix_transmission.StixTransmission(transmission_module, connection_dict, configuration_dict)
        results = []
        for query in dsl['queries']:
            search_result = transmission.query(query)
            if search_result["success"]:
                search_id = search_result["search_id"]

                if transmission.is_async():
                    time.sleep(1)
                    status = transmission.status(search_id)
                    if status['success']:
                        while status['progress'] < 100 and status['status'] == 'RUNNING':
                            logging.debug(status)
                            status = transmission.status(search_id)
                        logging.debug(status)
                    else:
                        raise RuntimeError("Fetching status failed")
                result = transmission.results(search_id, 0, 9)
                if result["success"]:
                    logging.debug("Search {} results is:\n{}".format(search_id, result["data"]))

                    # Collect all results
                    results += result["data"]
                else:
                    raise RuntimeError("Fetching results failed; see log for details")
            else:
                logging.error(str(search_result))
                raise Exception(str(search_result)) # TODO: how to deal with this situation

        # Translate results to STIX
        data_source = config['data_source']
        result = translation.translate(translation_module, 'results', data_source, json.dumps(results), {"stix_validator": True})
        return result


    def stix2dataframe(self, stix):
        def obj2df(obj):
            return [df_ for df_ in self.flatten_sco(obj) if isinstance(df_, pd.DataFrame)]

        dfs = []
        for ldf in list(map(lambda obj: obj2df(obj), stix['objects'])):
            dfs.extend(ldf)
        df = pd.concat(dfs)
        return df


    def flatten_sco(self, obj, viewname='observed-data'):
        # This method is contributed by @pcoccoli
        if obj['type'] != 'observed-data':
            return [obj]
        objs = obj['objects']
        nodes = {}

        # Create a node for each SCO
        for k, v in objs.items():
            nodes[k] = Node(k, fields=v)

        # Arrange the nodes into trees by references
        for k, v in objs.items():
            for attr, val in v.items():
                if attr.endswith('_ref'):
                    if nodes[val].parent:
                        # Already have a parent, so create a new node
                        nid = str(len(nodes))
                        new_node = Node(nid, parent=nodes[k], fields=nodes[val].fields)
                        nodes[nid] = new_node
                        nodes[nid].prefix = attr
                    else:
                        nodes[val].parent = nodes[k]
                        nodes[val].prefix = attr
                elif attr.endswith('_refs'):
                    for i, ref in enumerate(val):
                        nodes[ref].parent = nodes[k]
                        nodes[ref].prefix = attr + f'[{i}]'
                if attr == 'type':
                    assert val
                    assert val != ''

        # Walk each tree and output the "flat" STIX path to each SCO property
        roots = set([node.root for node in nodes.values()])
        result = json_normalize({key: obj[key] for key in obj.keys() if key != 'objects'})
        for root in roots:
            root_type = root.fields['type'] + ':'
            for node in PreOrderIter(root):
                tmp = node
                pre = ''
                while tmp.parent:
                    if hasattr(tmp, 'prefix'):
                        pre = tmp.prefix + '.' + pre
                    tmp = tmp.parent
                prefix = root.fields['type'] + ':' + pre
                for attr, val in node.fields.items():
                    if not (attr.endswith('_ref') or attr.endswith('_refs')):
                        if isinstance(val, list):
                            for i, v in enumerate(val):
                                result[prefix + attr + f'[{i}]'] = v
                        elif isinstance(val, dict):
                            # normalize dict and "merge" into result
                            result.update({f'{prefix}{attr}.{k}': v for k, v in json_normalize(val).items()})
                        else:
                            result[prefix + attr] = val
        return [result]


    def search_df(self, query: str, config_names: list):
        # TODO: parallelize this method.
        dfs = []
        for cfn in config_names:
            stix_bundle = self.stix_shiter_execute(cfn, query)
            if not stix_bundle:
                continue
            df_ = self.stix2dataframe(stix_bundle)
            df_['data_source'] = cfn
            dfs.append(df_)
        return pd.concat(dfs) if dfs else None


if __name__ == '__main__':
    qradar_config = {
        'connection': {
            "host": 'your-qradar-ip',
            "port": 443,
            "selfSignedCert": False,
            "options": {
                "timeout": 60,
            }
        },
        'configuration': {
            "auth": {
                "sec": 'your-qradar-token'
            }
        },
        'data_source': '{"type": "identity", "id": "identity--3532c56d-ea72-48be-a2ad-1a53f4c9c6d3", "name": "QRadar", "identity_class": "events"}'
    }
    ssdf = StixShifterDataFrame()

    ssdf.add_config('qradar', qradar_config)
    df = ssdf.search_df(query="[ipv4-addr:value = '127.0.0.1']", config_names=['qradar'])
