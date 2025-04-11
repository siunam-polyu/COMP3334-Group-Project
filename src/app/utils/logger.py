import utils.database

def logUserAction(userId, action, details=str()):
    try:
        query = 'INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)'
        utils.database.executeQuery(query, (userId, action, details))
    except Exception as error:
        print(f'[ERROR] Unable to insert the user action into the audit logs: {error}')
        raise error