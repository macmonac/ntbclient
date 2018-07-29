#!/usr/bin/env python
# -*- coding: utf-8 -*-


from __future__ import print_function
import sys
import os
from configobj import ConfigObj, flatten_errors
from validate import Validator


def test_spec(conf, spec):
    res = []
    config = ConfigObj(conf, configspec=spec)
    validator = Validator()
    results = config.validate(validator)

    if not results is True:
        for (section_list, key, _) in flatten_errors(config, results):
            if key is not None:
                res.append('The "%s" key in the section "%s" failed validation' % (key, ', '.join(section_list)))
            else:
                res.append('The following section was missing:%s ' % ', '.join(section_list))
    return res

filestotest = [{"conf": "../conf/ntbclient.conf", "spec": "../conf/ntbclient.conf.spec"},
              ]

basepath = os.path.join(os.getcwd(), os.path.dirname(__file__))
error = False
for filetotest in filestotest:
    conf = os.path.join(basepath, filetotest["conf"])
    spec = os.path.join(basepath, filetotest["spec"])
    res = test_spec(conf, spec)
    if len(res) > 0:
        error = True
        print("Validation error for %s ( spec: %s) :" % (conf, spec), file=sys.stderr)
        for r in res:
            print(r, file=sys.stderr)

if error:
    sys.exit(1)
sys.exit(0)
