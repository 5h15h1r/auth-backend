import pymysql
import pandas as pd
import datetime
from app.db_session import db_connection 
from fastapi import HTTPException
import uuid
from ua_parser import user_agent_parser
from app.config.app_config import get_config
from starlette import status
from typing import List
from app.auth.constants.enums import LoginEvents

class AuthDao:

    def get_user(self, email: str = None, mob_no: str = None, user_uuid: str = None, reset_flag=None):
        """
        Retrieve a user from the database based on email, mobile number, or user UUID.

        Parameters
        ----------
        email : str, optional
            Email address of the user (default: None)
        mob_no : str, optional
            Mobile number of the user (default: None)
        useruuId : str, optional
            UUID of the user (default: None)

        Returns
        -------
        user : pandas.Series
            A pandas Series object representing the retrieved user.

        Raises
        ------
        HTTPException
            - If the user is not found in the database (status_code=404)
            - If multiple entries are found for the given criteria (status_code=409)

        """
        conn = db_connection()
        cursor = conn.cursor()
        get_user_query = "SELECT * FROM user"
        params = []
        
        if email is not None:
            get_user_query += " WHERE email = %s"
            params.append(email)
        elif mob_no is not None:
            get_user_query += " WHERE mob_no = %s"
            params.append(mob_no)
        elif user_uuid is not None:
            get_user_query += " WHERE uuid = %s"
            params.append(user_uuid)
        
        try:
            cursor.execute(get_user_query, params)
            results = cursor.fetchall()
            columns = [col[0] for col in cursor.description]
            df = pd.DataFrame(results, columns=columns)
            

            if len(df) < 1:
                if reset_flag:
                    raise HTTPException(status_code=200, detail="If we find an account associated with this email, a password reset link will be sent to you shortly.")
                else:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found')
            elif len(df) > 1: 
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail='Multiple entries found')
            else:
                user = df.iloc[0]
                return user
        finally:
            cursor.close()
            conn.close()
        
    def get_role(self, roleId):
        """
        Retrieve a role from the database based on the role ID.

        Parameters
        ----------
        roleId : int
            ID of the role.

        Returns
        -------
        role : pandas.Series
            A pandas Series object representing the retrieved role.

        Raises
        ------
        HTTPException
            - If the role is not found in the database (status_code=404)
            - If multiple entries are found for the given role ID (status_code=500)

        """ 
        conn = db_connection()
        cursor = conn.cursor()
        query = "SELECT * FROM roles WHERE id = %s"
        
        try:
            cursor.execute(query, (roleId,))
            results = cursor.fetchall()
            columns = [col[0] for col in cursor.description]
            df = pd.DataFrame(results, columns=columns)
            
            if len(df) < 1: 
                raise HTTPException(status_code=404, detail='Role not found')
            elif len(df) > 1: 
                raise HTTPException(status_code=500, detail='Multiple entries found')
            else:
                role = df.iloc[0]
                return role
        finally:
            cursor.close()
            conn.close()

    def get_user_company(self, userUUId):
        """
        Retrieve the user company mapping associated with a user from the database based on the user UUID.

        Parameters
        ----------
        userUUId : str
            UUID of the user.

        Returns
        -------
        company : pandas.Series
            A pandas Series object representing the retrieved company.

        Raises
        ------
        HTTPException
            If the company for the user is not found in the database (status_code=404)
            If multiple entries are found for the given user UUID (status_code=500)

        """        
        conn = db_connection()
        cursor = conn.cursor()
        query = "SELECT * FROM company_users WHERE user_uuid = %s"
        
        try:
            cursor.execute(query, (userUUId,))
            results = cursor.fetchall()
            columns = [col[0] for col in cursor.description]
            df = pd.DataFrame(results, columns=columns)
            
            if len(df) < 1: 
                raise HTTPException(status_code=404, detail='Company for this user not found')
            elif len(df) > 1: 
                raise Exception('Multiple entries found')
            else:
                company = df.iloc[0]
                return company
        finally:
            cursor.close()
            conn.close()


    def create_user_session(self, userId, session_type, operating_system, browser, device_brand, device_model, ip_address):
        """
        Create a new user session in the database for the given user ID.

        Parameters
        ----------
        userId : int
            ID of the user.

        Returns
        -------
        sessionId : str
            UUID of the created session.
        sessionCreateTimestamp : datetime.datetime
            Timestamp of when the session was created.
        sessionExpiry : datetime.datetime
            Timestamp of when the session will expire.

        """
        conn = db_connection()
        cursor = conn.cursor()
        sessionCreateTimestamp = datetime.datetime.now()
        expiry_hours = get_config().TOKEN_EXPIRY_HOURS
        sessionExpiry = datetime.datetime.now() + datetime.timedelta(hours=expiry_hours)
        sessionId = "session_" + str(uuid.uuid4())
        query = "INSERT INTO user_session (user_id, uuid, login_timestamp, logout_timestamp, expiry, operating_system, browser, device_brand, device_model, session_type, ip_address) VALUES (%s, %s, %s, NULL, %s, %s, %s, %s, %s, %s, %s)"
        values = (userId, sessionId, sessionCreateTimestamp, sessionExpiry, operating_system, browser, device_brand, device_model, session_type, ip_address)
        cursor.execute(query, values)
        conn.commit()
        cursor.close()
        conn.close()
        return sessionId, sessionCreateTimestamp.timestamp(), sessionExpiry.timestamp()
    

    def update_user_session_with_token(self, session_uuid, jwt_token):
        conn = db_connection()
        cursor = conn.cursor()

        query = "UPDATE user_session SET jwt_token = %s WHERE uuid = %s"
        
        try: 
            cursor.execute(query, (jwt_token, session_uuid))
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            cursor.close()
            conn.close()
    
    def get_user_session(self, sessionId):
        """
        Retrieve a user session from the database based on the session UUID.

        Parameters
        ----------
        sessionId : str
            UUID of the session.

        Returns
        -------
        session : pandas.Series
            A pandas Series object representing the retrieved session.

        Raises
        ------
        HTTPException
            If the session is not found in the database (status_code=404)
            If multiple entries are found for the given session ID (status_code=409)

        """
        conn = db_connection()
        cursor = conn.cursor()
        query = "SELECT * FROM user_session WHERE uuid = %s"
        
        try:
            cursor.execute(query, (sessionId,))
            results = cursor.fetchall()
            columns = [col[0] for col in cursor.description]
            df = pd.DataFrame(results, columns=columns)
            
            if len(df) < 1: 
                raise HTTPException(status_code=404, detail='Session not found')
            elif len(df) > 1: 
                raise HTTPException(status_code=409, detail='Multiple entries found')
            else:
                session = df.iloc[0]
                return session
        finally:
            cursor.close()
            conn.close()
    
    def update_logout_timestamp(self, sessionId):
        """
        Update the logout timestamp of a user session in the database based on the session ID.

        Parameters
        ----------
        sessionId : str
            UUID of the session.

        Returns
        -------
        None

        """
        conn = db_connection()
        cursor = conn.cursor()
        currentTimestamp = datetime.datetime.now()
        query = "UPDATE user_session SET logout_timestamp = %s WHERE uuid = %s"
        
        try:
            cursor.execute(query, (currentTimestamp, sessionId))
            conn.commit()
        finally:
            cursor.close()
            conn.close()
        return

    def update_user_password(self, user_uuid, password):      
        conn = db_connection()
        cursor = conn.cursor()
        query = "UPDATE user SET hashed_password = %s WHERE uuid = %s"
        
        try:
            cursor.execute(query, (password, user_uuid))
            conn.commit()
        finally:
            cursor.close()
            conn.close()
        return

    def user_exists(self, email=None):
        """
        Check if a user with the given email exists in the database.

        Parameters
        ----------
        email : str
            email to check for existence.

        Returns
        -------
        bool
            True if the user exists, False otherwise.

        """
        conn = db_connection()
        cursor = conn.cursor()
        query = "SELECT * FROM user WHERE email = %s"
        
        try:
            cursor.execute(query, (email,))
            results = cursor.fetchall()
            columns = [col[0] for col in cursor.description]
            df = pd.DataFrame(results, columns=columns)
            
            user_rows = df.shape[0]
            if user_rows: 
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="email already taken")
            
            return False
        finally:
            cursor.close()
            conn.close()

    
    def create_user(self, user_uuid: str, first_name: str, last_name: str, email: str, designation: str, mob_no: str, hashed_password: str, company_uuid: str, is_active: int, role:str, role_id=None, mob_no_2=None):
        """
            Create a new user and insert their record into the database.

            Parameters
            ----------
            first_name : str
                The user's first name.
            last_name : str
                The user's last name.
            email : str
                The user's email address.
            designation: str
                The user's designation in their company.
            mob_no : str
                The user's primary mobile number.
            hashed_password : str
                The hashed password of the user.
            role_id : int, optional
                The role ID of the user (default is None).
            mob_no_2 : str, optional
                The user's secondary mobile number (default is None).

            Returns
            -------
            user_uuid: str
                uuid of new user created.

            Raises
            ------
            Exception
                If an error occurs while inserting the user record into the database.
            """
        conn = db_connection()
        cursor = conn.cursor()

        query = """
            INSERT INTO user (uuid, first_name, last_name, role_id, role, email, designation, mob_no, hashed_password, mob_no_2, company_uuid, is_active)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """

        values =  (user_uuid, first_name, last_name, role_id, role, email, designation, mob_no, hashed_password, mob_no_2, company_uuid, is_active)

        try:
            cursor.execute(query, values)
            conn.commit()
            return user_uuid
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            cursor.close()
            conn.close()

    def get_company_user_roles(self, company_id):
        db = db_connection()
        cursor = db.cursor()
        sql = "SELECT r.name AS user_role, COUNT(u.role_id) AS count FROM user AS u JOIN roles AS r ON " \
              "u.role_id = r.id WHERE u.company_uuid = %s GROUP BY r.name;"
        
        try:
            cursor.execute(sql, (company_id,))
            results = cursor.fetchall()
            columns = [col[0] for col in cursor.description]
            df = pd.DataFrame(results, columns=columns)
            return df
        finally:
            cursor.close()
            db.close()
    
    def get_token_from_session_uuid(self, session_uuid: str):
        db = db_connection()
        cursor = db.cursor()

        try:
            sql = "SELECT * FROM user_session WHERE uuid = %s"
            cursor.execute(sql, (session_uuid,))
            results = cursor.fetchall()
            columns = [col[0] for col in cursor.description]
            df = pd.DataFrame(results, columns=columns)
            
            if len(df) < 1: 
                raise HTTPException(status_code=404, detail='Session not found')
            elif len(df) > 1: 
                raise HTTPException(status_code=409, detail='Multiple entries found')
            else:
                session_row = df.iloc[0]
                token = session_row.get('jwt_token')
                return token
        finally: 
            cursor.close()
            db.close()

    def update_user(self, user_uuid: str, first_name: str = None, last_name: str = None, email: str = None, mob_no: str = None, designation: str = None, role_id: int = None, status: str = None, is_active: int = None):
        db = db_connection()
        cursor = db.cursor()

        try:
            update_parts = []
            params = []
            
            if first_name is not None:
                update_parts.append("first_name = %s")
                params.append(first_name)
            if last_name is not None: 
                update_parts.append("last_name = %s")
                params.append(last_name)
            if email is not None:
                update_parts.append("email = %s")
                params.append(email)
            if mob_no is not None:
                update_parts.append("mob_no = %s")
                params.append(mob_no)
            if designation is not None:
                update_parts.append("designation = %s")
                params.append(designation)
            if role_id is not None:
                update_parts.append("role_id = %s")
                params.append(role_id)
            if status is not None:
                update_parts.append("status = %s")
                params.append(status)
            if is_active is not None:
                update_parts.append("is_active = %s")
                params.append(is_active)

            if update_parts:
                # Add user_uuid as the last parameter
                params.append(user_uuid)
                update_sql = f"UPDATE user SET {', '.join(update_parts)} WHERE uuid = %s"
                cursor.execute(update_sql, params)
                db.commit()

                affected_rows = cursor.rowcount
            else:
                affected_rows = 0
            return affected_rows
        finally: 
            cursor.close()
            db.close()

    def get_bulk_users(self, user_ids: List[str], company_uuid: str, search_value: str = None):
        db = db_connection()
        cursor = db.cursor()
        try: 
            if user_ids:
                if len(user_ids) == 1:
                    query = "SELECT * FROM user WHERE uuid = %s"
                    cursor.execute(query, (user_ids[0],))
                else:
                    # Create placeholder string for multiple IDs
                    placeholders = ', '.join(['%s'] * len(user_ids))
                    query = f"SELECT * FROM user WHERE uuid IN ({placeholders})"
                    cursor.execute(query, user_ids)
                
                results = cursor.fetchall()
                columns = [col[0] for col in cursor.description]
                dfs = pd.DataFrame(results, columns=columns)
            elif company_uuid:
                if search_value:
                    query = "SELECT * FROM user WHERE company_uuid = %s AND (first_name LIKE %s OR last_name LIKE %s)"
                    search_pattern = f"%{search_value}%"
                    cursor.execute(query, (company_uuid, search_pattern, search_pattern))
                else:
                    query = "SELECT * FROM user WHERE company_uuid = %s"
                    cursor.execute(query, (company_uuid,))
                
                results = cursor.fetchall()
                columns = [col[0] for col in cursor.description]
                dfs = pd.DataFrame(results, columns=columns)
            else:
                dfs = pd.DataFrame()

            if len(dfs) < 1: 
                raise HTTPException(status_code=404, detail='Users not found')
            users_list = dfs.to_dict(orient='records')
            return users_list
        finally: 
            cursor.close()
            db.close()

    def log_login_attempts(self, user_id, event):
        
        db = db_connection()
        cursor = db.cursor()
        insert_query =  """
                            INSERT INTO login_attempts(user_id, event) 
                            VALUES (%s ,%s)
                        """
        try:
            cursor.execute(insert_query, (user_id, event))
            db.commit()
        except Exception as e:
            db.rollback()
            return {"status": 500, "message": f"Some error occured {e} "}
        finally:
            cursor.close()
            db.close()
    

    def get_login_attempts(self, user_id):
        
        db = db_connection()
        get_query = """
                        SELECT COUNT(*) AS failed_attempts
                        FROM (
                            SELECT event
                            FROM login_attempts
                            WHERE user_id = %s
                            ORDER BY created_at DESC
                            LIMIT 3
                        ) AS recent_attempts
                        WHERE event = %s
                    """
        
        try:
            df = pd.read_sql(get_query, db, params=(user_id, LoginEvents.LOGIN_FAILED))
            return df["failed_attempts"].iloc[0]
        
        except Exception as e:
            print(f"An error occurred: {e}")
            return {"status": 500, "message": f"Some error occured {e} "}
        
        finally:
            db.close()

auth_dao = AuthDao()


