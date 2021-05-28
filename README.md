## central-tools

Small tools to handle Central sessions/data structures.
Edit `central_config.py` and specify the cluster name and username to access.

<br><br>
## centralsession.py

This is the main class required by most of the scripts in this repository.
It manages Central UI/API sessions and API tokens.

If directly called it will get API token and store it to a cache file.

#### Syntax
```
  centralsession.py [--debug|--info]
```

