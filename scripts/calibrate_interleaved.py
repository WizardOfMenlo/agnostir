#!/usr/bin/env python3
"""Current four-code prime-field presets, using the audited distance scripts.

These numerical ideal-ensemble calculations are not fixed-instance distance
certificates or a complete Fiat–Shamir soundness proof.
"""
import importlib.util
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULUS = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141',16)


def load(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'distance-analysis'/f'{name}.py')
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    bf,bd,era=(load(name) for name in ('basefold','brakedown','era'))
    n,field_log,bits=65536,255.999,102
    base=bd.check_recursive(n,.04,1.05,.0009,5,42,modulus=MODULUS,security=bits)
    brakedown=bd.check_recursive(n,.3,2,.1,14,28,modulus=MODULUS,security=bits)
    assert base['bound_passes'] and brakedown['bound_passes']
    bf_delta=bf.distance_for_setup_bits(field_log,2,16,bits)
    length=4*int(n*1.05)
    c=era.compute_c_from_q_bound(4,bits,.0009,math.log2(length),field_log)
    gamma=era.compute_gamma_from_n_bound(4,c,bits,math.log2(length))
    candidate=era.solve_details(c,4,gamma,.0009)
    assert candidate and candidate['delta'] >= .22037 and bf_delta >= .20106
    def queries(delta):
        return math.ceil(-300/math.log2(1-delta))
    result={
        'field':'secp256k1 scalar field', 'field_modulus':str(MODULUS),
        'field_log2_lower_bound':field_log,'row_message_length':n,
        'basefold':{'setup_bits':bits,'per_level_lambda':106,
                    'numerical_distance':bf_delta,'distance_used':.20106,
                    'queries':queries(.20106)},
        'brakedown':{**brakedown,'distance_used':.1,'queries':queries(.1)},
        'ea':{'inverse_rate':2,'prob_multiplier':18,'distance_used':.1,
              'queries':queries(.1),
              'scope':'inherited distance assumption; no new finite-length setup certificate'},
        'era':{'base':base,'calcdist_bits':bits,'c':c,'gamma':gamma,**candidate,
               'distance_used':.22037,'queries':queries(.22037)},
        'scope':'numerical ideal-ensemble bounds; ERA has no certified all-roots isolation; not complete FS soundness',
    }
    print(json.dumps(result,indent=2,allow_nan=False))


if __name__=='__main__':
    main()
