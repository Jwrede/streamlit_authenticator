from typing import Optional
import cognitojwt
from jose import JWTError
import streamlit as st
from .encrypted_cookie_manager import EncryptedCookieManager
import requests
import base64
import json


class Authenticator:
    # ------------------------------------
    # Authenticator.activate activates authentification for the streamlit app
    # ------------------------------------

    def __init__(
        self, 
        cognito_domain,
        client_id,
        client_secret,
        app_uri,
        pool_id,
        region,
        encryption_password = "password"
    ):
        self.cognito_domain = cognito_domain
        self.client_id = client_id
        self.client_secret = client_secret
        self.app_uri = app_uri
        self.pool_id = pool_id
        self.region = region
        self.cookie_manager = EncryptedCookieManager(prefix="streamlit/", password=encryption_password)
        if not self.cookie_manager.ready():
            st.stop()

    def initialise_st_state_vars(self):
        """
        Initialise Streamlit state variables.

        Returns:
            Nothing.
        """
        logout = st.experimental_get_query_params().get("logout")
        if "tokens" not in self.cookie_manager or logout is not None:
            self.cookie_manager["tokens"] = json.dumps({})
        if "user_groups" not in self.cookie_manager or logout is not None:
            self.cookie_manager["user_groups"] = json.dumps([])
        self.cookie_manager.save()


    def get_auth_code(self):
        """
        Gets auth_code state variable.

        Returns:
            Nothing.
        """
        auth_query_params = st.experimental_get_query_params()
        try:
            auth_code = dict(auth_query_params)["code"][0]
        except (KeyError, TypeError):
            auth_code = ""

        return auth_code


    def get_user_tokens(self, auth_code):
        """
        Gets user tokens by making a post request call.

        Args:
            auth_code: Authorization code from cognito server.

        Returns:
            {
            'access_token': access token from cognito server if user is successfully authenticated.
            'id_token': access token from cognito server if user is successfully authenticated.
            }

        """

        # Variables to make a post request
        token_url = f"{self.cognito_domain}/oauth2/token"
        client_secret_string = f"{self.client_id}:{self.client_secret}"
        client_secret_encoded = str(
            base64.b64encode(client_secret_string.encode("utf-8")), "utf-8"
        )
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {client_secret_encoded}",
        }
        body = {
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code": auth_code,
            "redirect_uri": self.app_uri,
        }

        token_response = requests.post(token_url, headers=headers, data=body)
        try:
            access_token = token_response.json()["access_token"]
            id_token = token_response.json()["id_token"]
        except (KeyError, TypeError):
            access_token = ""
            id_token = ""

        return access_token, id_token


    def get_user_info(self):
        """
        Gets user info from aws cognito server.

        Args:
            access_token: string access token from the aws cognito user pool
            retrieved using the access code.

        Returns:
            userinfo_response: json object.
        """
        access_token = json.loads(self.cookie_manager["tokens"]).get("access_token")
        if access_token:
            userinfo_url = f"{self.cognito_domain}/oauth2/userInfo"
            headers = {
                "Content-Type": "application/json;charset=UTF-8",
                "Authorization": f"Bearer {access_token}",
            }

            userinfo_response = requests.get(userinfo_url, headers=headers)

            return userinfo_response.json()


    # Ref - https://gist.github.com/GuillaumeDerval/b300af6d4f906f38a051351afab3b95c
    def pad_base64(self, data):
        """
        Makes sure base64 data is padded.

        Args:
            data: base64 token string.

        Returns:
            data: padded token string.
        """
        missing_padding = len(data) % 4
        if missing_padding != 0:
            data += "=" * (4 - missing_padding)
        return data

    def get_user_groups(self, id_token):
        """
        Decode id token to get user cognito groups.

        Args:
            id_token: id token of a successfully authenticated user.

        Returns:
            user_groups: a list of all the cognito groups the user belongs to.
        """
        user_groups = []
        if id_token != "":
            header, payload, signature = id_token.split(".")
            printable_payload = base64.urlsafe_b64decode(self.pad_base64(payload))
            payload_dict = json.loads(printable_payload)
            try:
                user_groups = list(dict(payload_dict)["cognito:groups"])
            except (KeyError, TypeError):
                pass
        return user_groups


    def activate(self) -> Optional[dict]:
        """
        Sets the streamlit state variables after user authentication.
        
        Returns:
            Nothing.
        """
        self.initialise_st_state_vars()
        auth_code = self.get_auth_code()
        access_token, id_token = self.get_user_tokens(auth_code)
        user_groups = self.get_user_groups(id_token)

        if access_token != "":
            self.cookie_manager["tokens"] = json.dumps({"access_token": access_token, "id_token": id_token})
            self.cookie_manager["user_groups"] = json.dumps(user_groups)
            self.cookie_manager.save()

        return self.get_user_info()


    def check_access(self):
        """
        Checks whether the current user is logged into Cognito

        Returns:
            bool
        """
        tokens = json.loads(self.cookie_manager.get("tokens"))
        if tokens is not None and "access_token" in tokens and "id_token" in tokens:
            return self.verify_token(tokens["id_token"])


    def verify_token(self, id_token):
        """
        Checks if the id_token is valid and not expired yet

        Returns:
            bool
        """
        try:
            cognitojwt.decode(id_token, self.region, self.pool_id, self.client_id)
            return True
        except (cognitojwt.exceptions.CognitoJWTException, JWTError) as e:
            return False


    def check_role(self, role):
        cookie_user_groups = self.cookie_manager.get("user_groups")
        if cookie_user_groups is not None:
            return role in json.loads(cookie_user_groups)
        else:
            return False

    # -----------------------------
    # Login/ Logout HTML components
    # -----------------------------
    def login_button(self, logout=False):
        """

        Returns:
            Html of the login button.
        """
        html_css_login = """
        <style>
        .button-login {
        background-color: skyblue;
        color: white !important;
        padding: 1em 1.5em;
        text-decoration: none;
        text-transform: uppercase;
        }

        .button-login:hover {
        background-color: #555;
        text-decoration: none;
        }

        .button-login:active {
        background-color: black;
        }

        </style>
        """
        login_link = f"{self.cognito_domain}/login?client_id={self.client_id}&response_type=code&scope=email+openid&redirect_uri={self.app_uri}"
        logout_link = f"{self.cognito_domain}/logout?client_id={self.client_id}&redirect_uri={self.app_uri}&logout_uri={self.app_uri}%3Flogout=true"

        html_button_login = (
            html_css_login
            + f"<a href='{login_link}' class='button-login' target='_self'>Log In</a>"
        )
        html_button_logout = (
            html_css_login
            + f"<a href='{logout_link}' class='button-login' target='_self'>Log Out</a>"
        )
        return st.sidebar.markdown(f"{html_button_logout if logout else html_button_login}", unsafe_allow_html=True)



