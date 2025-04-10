import utils.database

def logUserAction(userId, action):
    try:
        query = 'INSERT INTO audit_logs (user_id, action) VALUES (?, ?)'
        utils.database.executeQuery(query, (userId, action))
    except Exception as error:
        print(f'[ERROR] Unable to insert the user action into the audit logs: {error}')
        raise error