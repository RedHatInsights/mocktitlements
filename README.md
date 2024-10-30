# Simple server for mocking Entitlements

## Testing
To test locally you can run `rebuild_and_test.sh`.

If you want to run and debug the tests in VSCode first start the services with:

```sh
docker compose -f deployments/compose.yaml up -d --build
```

Create a launch task in VSCode with this config:

```json
{
    "version": "0.2.0",
    "configurations": [
       {
          "type": "node",
          "request": "launch",
          "name": "Debug Mocha Tests",
          "program": "${workspaceFolder}/test/node_modules/mocha/bin/_mocha",
          "args": [
             "test.js"
          ],
          "cwd": "${workspaceFolder}/test",
          "console": "integratedTerminal",
          "internalConsoleOptions": "openOnSessionStart"
       }
    ]
 }
```

You can now run the Debug Mocha Tests task in VSCode to run the tests. You can also set breakpoints, inspect variables, etc.