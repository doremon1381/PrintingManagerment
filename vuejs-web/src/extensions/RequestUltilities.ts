import { router } from "@/router";
import { useAuthStore } from "@/stores/auth";
//import { useAuthStore } from "@/stores/auth";
import axios, { type AxiosResponse, type RawAxiosRequestHeaders } from "axios";
//import AxiosResponse from "axios";
import { ref } from "vue";

// authInfo = useAuthStore();
type NX = (value: void) => void;
type HR = (value: AxiosResponse) => void;
const webServerTestRequest = "https://localhost:7209";

function useAxiosGet(uri: string, handleResponse: HR, nextRequest: NX)
{
   const data = ref(null);

   axios.get(uri).then(response => {
       //data.value = response.data;
       handleResponse(response);
   }).catch(error => {
       console.log(error);
       // TODO: if 401, use router to redirect
   }).then(()=> {
       nextRequest();
   });

   return data;
}

function useAxiosGetWithHeaders(uri: string, headers: RawAxiosRequestHeaders, handleResponse: HR, nextRequest: NX)
{
   //const data = ref(null);

   axios.get(uri,{
       headers
   }).then(response => {
       //data.value = response.data;
       handleResponse(response);
   }).catch(error => {
       console.log(error);
       // TODO: if 401, use router to redirect
   }).then(()=> {
       nextRequest();
   });

   //return data;
}

function useAxiosGetWithAccessToken(api: string, handleResponse: HR, nextRequest: NX)
{
   const data = useAuthStore();

   axios.get(webServerTestRequest + api, {
    headers:{
        Authorization: "Bearer " + data.user.access_token
    }
   }).then(response => {
       //data.value = response.data;
       handleResponse(response);
   }).catch(error => {
       console.log(error);
       // TODO: if 401, use router to redirect
       if (error.response.status === 401)
       {
            router.push('/auth/login');
       }
   }).then(()=> {
       nextRequest();
   });
}

 export { useAxiosGet, useAxiosGetWithHeaders, useAxiosGetWithAccessToken };
