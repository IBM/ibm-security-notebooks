# Stix-Shifter notebooks

# Getting started

## Prerequisites

1. Python 3
1. Jupyter Notebook, JupyterHub, or Jupyter Lab


## Installing

To use the package, simply install it with `pip` in a notebook cell.
```
!pip install git+https://github.com/IBM/ibm-security-notebooks.git
```


## How to use Stix-Shiter-DataFrame API

We need to provide configuration, and connection setting for different connector before calling method `search_df` to fetch data. The following is an example to demonstrate how to setup Qradar connector for stix-shifter-dataframe.

```
from pyclient.stix_shifter_dataframe import StixShifterDataFrame
qradar_config = {
    'connection': {
        "host": 'Your-Qradar-IP',
        "port": 443,
        "selfSignedCert": False,
        "options": {
            "timeout": 60,
        }
    },
    'configuration': {
        "auth": {
            "sec": 'Your-Qradar-Token'
        }
    },
    'data_source': '{"type": "identity", "id": "identity--3532c56d-ea72-48be-a2ad-1a53f4c9c6d3", "name": "QRadar", "identity_class": "events"}'
}
ssdf = StixShifterDataFrame()
ssdf.add_config('qradar', qradar_config)
```

Users can focus on high-level objectives when invoking the methods. For instance, the method `search_df` will retrieve results of STIX queries (via stix-shifter), and convert them into tables suitable for analyses (via a method called stix2dataframe).
```
df = ssdf.search_df(query="[ipv4-addr:value = '127.0.0.1']", config_names=['qradar'])
```

# Examples
This notebook is used to demonstrate how to fetch data from data sources by stix-shifter-dataframe. After that we can do some basic operation on the dataframe.
* [Load Dataframe](https://github.com/IBM/ibm-security-notebooks/blob/master/stix-shifter-notebooks/basic_df_analysis.ipynb)