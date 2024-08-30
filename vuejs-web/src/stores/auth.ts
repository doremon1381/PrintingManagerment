import { defineStore } from 'pinia';
import { router } from '@/router';
import { ref } from 'vue';
//import { fetchWrapper } from '@/utils/helpers/fetch-wrapper';
import { AxiosHeaders } from 'axios';
import { ByteArrayToBase64NoPadding, StringUTF8ToByteArray, ByteArrayToBase64, GenerateRandomStringWithLength } from '@/extensions/RNGCryptoUltilities.js';
//import { useIdentityOptions } from '@/stores/identityOptions';
//import { tokenVerifyer } from '@/stores/JwtValidate';
import axios from 'axios';
//import { mapMutations } from 'vuex'
//import { useStore } from 'vuex'
import { useAxiosGet, useAxiosGetWithHeaders } from '@/extensions/RequestUltilities';

const authorizeEndpoint = "https://localhost:7180/oauth2/authorize";
const redirecUri = "http://localhost:5173";
const clientId = "PrintingManagermentServer";

const baseUrl = `${import.meta.env.VITE_API_URL}/users`;
const state :string = GenerateRandomStringWithLength(32);
//const store = useStore();

function ValidateState(st: string)
{
    if (st !== state)
    {
      return false;
    }
    else 
      return true;
}

function parseJwt (token: string) {
  const base64Url = token.split('.')[1];
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  const jsonPayload = decodeURIComponent(window.atob(base64).split('').map(function(c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
  }).join(''));

  return JSON.parse(jsonPayload);
}

//const identityOptions = useIdentityOptions();
const authorizationCodeResponse = ref(null);
const clientState = ref("");
var authCodeRequest = "";
var clientExchangeCodeRequest= "";

export const useAuthStore = defineStore({
  id: 'auth',
  state: () => {
    return {
      // initialize state from local storage to enable user to stay logged in
      /* eslint-disable-next-line @typescript-eslint/ban-ts-comment */
      // @ts-ignore
      user: JSON.parse(localStorage.getItem('user')),
      returnUrl: null
    }
  },
  actions: {
    async login(username: string, password: string) {
      // const user = await fetchWrapper.post(`${baseUrl}/authenticate`, { username, password });
      const authorization = ByteArrayToBase64(StringUTF8ToByteArray(username + ":" + password));
      //const authorizationRequest = authorizeEndpoint + "?response_type=code&scope=openid%20profile%20email%20offline_access&redirect_uri=" + redirecUri + "&client_id="+ clientId + "&state=" + state;
      const webServerTestRequest = "https://localhost:7209";
      
      useAxiosGet(webServerTestRequest, response => {
        // console.log(response.data);
        let location = "";
        const headers = response.headers;
        //console.log("401 client response: "+headers);

        if (headers instanceof AxiosHeaders && headers.has('location')) {
          location = headers["location"];
          
          authCodeRequest = location + "&state=" + state + "&response_type=code&scope=openid%20profile%20email%20offline_access";
          // console.log("id server: " + authCodeRequest);

          clientState.value = response.data.client_state;
          // console.log("clientState: " + clientState.value);
        }},() => {
          useAxiosGetWithHeaders(authCodeRequest, {
              //state: state,
              Authorization: "Basic "+ authorization
            }, response => {
            authorizationCodeResponse.value = response.data.code;  
            // console.log(response.data.location);
            if(ValidateState(response.data.state))
            {
              //console.log("code: " + response.data.code);
            }
            const headers = response.headers;
            //console.log(headers);
            if (headers instanceof AxiosHeaders && headers.has('location')) {
                clientExchangeCodeRequest = headers["location"] + "&client_state=" + clientState.value + "&state=" + state;
                console.log(clientExchangeCodeRequest);
            }
          }, ()=>{
            useAxiosGet(clientExchangeCodeRequest, response => {
              //console.log(response);
              const user = parseJwt(response.data);
              user.access_token = response.data;
              // console.log(user);
              // TODO: do it later
              //const isVerified = tokenVerifyer(response.data);
              // update pinia state
              this.user = user;
              // store user details and jwt in local storage to keep user logged in between page refreshes
              localStorage.setItem('user', JSON.stringify(user));
              // redirect to previous url or default to home page
              router.push(this.returnUrl || '/dashboard/default');
            }, () => {})
          })
            
      })
    },
    logout() {
      this.user = null;
      localStorage.removeItem('user');
      router.push('/auth/login');
    },
    async signUp(name: string, fullName: string, username: string , password: string, email: string){
      // console.log(encodeURI(name));
      // console.log(encodeURI(username));
      // console.log(encodeURI(fullName));
      // console.log(encodeURI(email));
      const authorization = ByteArrayToBase64(StringUTF8ToByteArray(username + ":" + password));
      axios.get(authorizeEndpoint + "?prompt=create", {
        headers:{
          Register: "Basic " + authorization,
          Email: email,
          Name: encodeURI(name),
          FullName: encodeURI(fullName)
        }
      }).then(response => {
        console.log(response);
        router.push(this.returnUrl || '/auth/login');
      }).catch(error => {
        console.log(error);
      })
    }
  }
});
