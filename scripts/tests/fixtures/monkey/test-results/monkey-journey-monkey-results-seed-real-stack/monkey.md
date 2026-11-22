### monkey results, seed 1234

Replay:

```sh
MONKEY_SEED=1234 MONKEY_STEPS=60 bash scripts/monkey/monkey.sh run https://localhost DIR --grep "monkey results seed"
```

Problems:

```
step 7: uncaught error: Cannot read properties of undefined (reading 'name')
```

Actions:

```
1. click tab "SBOM"
2. press Escape
```
