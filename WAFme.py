#!//usr/bin/env python
# -------------------------------------------------------------------------------
# Name:        ModSecruity audit log extractor
# Purpose:     Build ModSecurity rules to whitelist CRS
#
# Author:      mleos
#
# Created:     5/10/2017
#
# Copyright:   (c) spartantri cybersecurity
# Licence:     Apache2
# -------------------------------------------------------------------------------

import json

def find_values(id, json_repr):
    results = []

    def _decode_dict(a_dict):
        try: results.append(a_dict[id])
        except KeyError: pass
        return a_dict

    json.loads(json_repr, object_hook=_decode_dict)  # Return value ignored.
    return results
