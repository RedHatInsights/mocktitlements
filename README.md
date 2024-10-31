# Simple server for mocking Entitlements

## Testing

Tests in this project are End to End (E2E) only. They're written in Javascript using the Mocha test framework, using Chai to make assertions. 

To run these tests, you need to bring up instances of both Keycloak and PostgreSQL, and of course Mocktitlements.

You can start the services using the compose template with:

```sh
docker compose -f deployments/compose.yaml up -d --build
```

If you're using a SELinux enabled system (like Fedora) make sure you export the required environment variable to set the appropriate flags for the volume mount. There's a env file you can use (`deployments/podman-compose-env`).

The command would then become:

```
docker compose -f deployments/compose.yaml --env-file deployments/podman-compose-env up -d --build
```

You would need to install the npm packages to run the tests, including the dev dependencies. You can run the following command to achieve it:

```
npm i --save-dev --prefix test
```

To run the tests, simply run:

```
npm --prefix test test
```

When testing locally, it is usually the case you may leave the Keycloak and PostgreSQL instances running, and just need to recreate Mocktitlements. You can run `rebuild_and_test.sh` to achieve that.

If you want to run and debug the tests in VSCode first :

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
