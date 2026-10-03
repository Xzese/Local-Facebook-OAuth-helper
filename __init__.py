if __package__:
    from .auth_server import *
else:
    # Support direct checkouts whose directory is not a Python package name.
    from auth_server import *
