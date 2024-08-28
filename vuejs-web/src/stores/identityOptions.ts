import { defineStore } from 'pinia';
//import { router } from '@/router';
import axios from "axios";
import {GenerateRandomStringWithLength} from '@/extensions/RNGCryptoUltilities.js'

const webServerUrl = "https://localhost:7209";
const state = GenerateRandomStringWithLength(32);

interface UserToken{
    Username: string;

}

// TODO: this store will be used for getting authorization code and exchanging it to id token
export const useIdentityOptions = defineStore("UserManager", {
    state: ()=> {
        return{
            // TODO: I will add something later
            authorizationCode: "",

        }
    },
    getters:{
      getLocation(state){
        // TODO
        //return state.location;
      }
    },
    actions:{
        SendUnauthorizeRequestToGetLocation(){
            axios.get(webServerUrl, {
                headers:{
                    'state': state,
                    //"Access-Control-Allow-Origin":  "*",
                    // "Access-Control-Allow-Methods": "OPTIONS, DELETE, POST, GET, PATCH, PUT",
                    //"Access-Control-Request-Headers": "Origin",
                }
            })
            .then()
            // TODO: because if a request without "authorization" header or authorization with bearer token in header, server will return a redirect to identity location
            .catch(error => {
                // TODO: for test
                //console.log(error);
                const responseState = error.response.headers["state"];
                if (responseState != null
                    || responseState != "")
                {
                    if (state === responseState)
                    {
                        this.location = error.response.headers["identitylocation"];
                        //console.log(this.location);
                        //loc = error.response.headers["identitylocation"];
                        //console.log(loc);
                    }

                    //return;
                }
            });
        },
    }
});