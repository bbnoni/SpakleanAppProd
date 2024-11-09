from sqlalchemy.exc import OperationalError
from sqlalchemy import event
from sqlalchemy.engine import Engine

@event.listens_for(Engine, "engine_connect")
def ping_connection(connection, branch):
    if branch:
        return  # branch=True indicates a sub-connection, skip ping for these
    try:
        connection.scalar("SELECT 1")  # Simple query to test the connection
    except OperationalError as ex:
        # MySQL error codes 2006 and 2013 indicate lost connections
        if "2006" in str(ex) or "2013" in str(ex):
            connection.invalidate()  # Mark the connection as invalid for reconnect
        else:
            raise  # Re-raise if it's a different error
