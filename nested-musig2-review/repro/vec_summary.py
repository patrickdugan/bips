import json, sys, collections
for name in ['key_agg_vectors.json','nonce_agg_vectors.json','sign_verify_vectors.json','sig_agg_vectors.json']:
    v = json.load(open(name))
    print('=====', name, 'top-level keys:', list(v.keys()))
    for k in v:
        if isinstance(v[k], list) and v[k] and isinstance(v[k][0], str):
            lens = collections.Counter(len(s)//2 for s in v[k])
            print(f'  {k}: {len(v[k])} entries, byte lengths {dict(lens)}')
    for grp in [g for g in v if g.endswith('test_cases')]:
        print(f'  -- {grp}: {len(v[grp])} cases')
        for c in v[grp]:
            dup = ''
            lk = c.get('leaf_key_indices', {})
            if lk and len(set(lk.values())) != len(lk): dup = ' DUP-KEYS'
            err = c.get('error')
            errs = f" err={err.get('operation','')}/{err.get('type','')}/{err.get('contrib', err.get('message',''))}" if err else ''
            print(f"    {c.get('id')}: tree={c.get('tree')} tweaks={len(c.get('tweaks',[]))} is_xonly={c.get('is_xonly')} msg_index={c.get('msg_index')} signer={c.get('signer', c.get('participant',''))}{dup}{errs} {c.get('comment','')[:100]}")
