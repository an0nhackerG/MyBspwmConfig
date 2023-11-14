(()=>{var e={954:e=>{(()=>{"use strict";var t={68800:(e,t,r)=>{Object.defineProperty(t,"__esModule",{value:!0}),t.isWebauthnResult=t.isWebauthnResultSuccess=t.WebauthnOperationType=t.WebauthnErrorName=t.WebAuthnStatus=t.WebAuthnCallTypes=void 0;var n,o,i,a=r(38945);function u(e){return"object"==typeof e&&null!==e&&"status"in e&&"success"===e.status&&"value"in e&&"object"==typeof e.value&&null!==e.value}Object.defineProperty(t,"WebAuthnCallTypes",{enumerable:!0,get:function(){return a.WebAuthnCallTypes}}),(i=t.WebAuthnStatus||(t.WebAuthnStatus={})).Success="Success",i.Error="Error",(o=t.WebauthnErrorName||(t.WebauthnErrorName={})).NotSupportedError="NotSupportedError",o.SecurityError="SecurityError",o.NotAllowedError="NotAllowedError",o.InvalidStateError="InvalidStateError",o.UnknownError="UnknownError",(n=t.WebauthnOperationType||(t.WebauthnOperationType={})).Create="create",n.Get="get",t.isWebauthnResultSuccess=u,t.isWebauthnResult=function(e){return u(e)||function(e){return"object"==typeof e&&null!==e&&"status"in e&&"useFallback"===e.status}(e)||function(e){return"object"==typeof e&&null!==e&&"status"in e&&"error"===e.status&&"errorName"in e&&"string"==typeof e.errorName}(e)}},14043:function(e,t,r){var n=this&&this.__createBinding||(Object.create?function(e,t,r,n){void 0===n&&(n=r);var o=Object.getOwnPropertyDescriptor(t,r);o&&!("get"in o?!t.__esModule:o.writable||o.configurable)||(o={enumerable:!0,get:function(){return t[r]}}),Object.defineProperty(e,n,o)}:function(e,t,r,n){void 0===n&&(n=r),e[n]=t[r]}),o=this&&this.__exportStar||function(e,t){for(var r in e)"default"===r||Object.prototype.hasOwnProperty.call(t,r)||n(t,e,r)};Object.defineProperty(t,"__esModule",{value:!0}),o(r(68800),t)},38945:(e,t)=>{var r,n,o,i,a,u,s,l,c;Object.defineProperty(t,"__esModule",{value:!0}),t.StartWebAuthnAuthenticationError=t.RemoveWebAuthnAuthenticatorError=t.DisableWebAuthnAuthenticationError=t.OpenSessionWithWebAuthnAuthenticatorError=t.InitOpenSessionWithWebAuthnAuthenticatorError=t.RefreshAvailableWebAuthnAuthenticatorsError=t.RefreshWebAuthnAuthenticatorsError=t.RegisterWebAuthnAuthenticatorError=t.InitRegisterWebAuthnAuthenticatorError=t.EnableWebAuthnAuthenticationError=t.InitEnableWebAuthnAuthenticationError=t.WebAuthnCallTypes=void 0,(c=t.WebAuthnCallTypes||(t.WebAuthnCallTypes={})).CREATE="webauthn.create",c.GET="webauthn.get",(t.InitEnableWebAuthnAuthenticationError||(t.InitEnableWebAuthnAuthenticationError={})).UNKNOWN_ERROR="UNKNOWN_ERROR",(l=t.EnableWebAuthnAuthenticationError||(t.EnableWebAuthnAuthenticationError={})).UNKNOWN_ERROR="UNKNOWN_ERROR",l.USER_HAS_OTP="USER_HAS_OTP",l.WEBAUTHN_SERVICE_INIT_FAILED="WEBAUTHN_SERVICE_INIT_FAILED",(t.InitRegisterWebAuthnAuthenticatorError||(t.InitRegisterWebAuthnAuthenticatorError={})).UNKNOWN_ERROR="UNKNOWN_ERROR",(s=t.RegisterWebAuthnAuthenticatorError||(t.RegisterWebAuthnAuthenticatorError={})).USER_HAS_OTP="USER_HAS_OTP",s.UNKNOWN_ERROR="UNKNOWN_ERROR",(t.RefreshWebAuthnAuthenticatorsError||(t.RefreshWebAuthnAuthenticatorsError={})).UNKNOWN_ERROR="UNKNOWN_ERROR",(u=t.RefreshAvailableWebAuthnAuthenticatorsError||(t.RefreshAvailableWebAuthnAuthenticatorsError={})).UNKNOWN_ERROR="UNKNOWN_ERROR",u.MISSING_SESSION_KEYS_IN_STORE="MISSING_SESSION_KEYS_IN_STORE",(a=t.InitOpenSessionWithWebAuthnAuthenticatorError||(t.InitOpenSessionWithWebAuthnAuthenticatorError={})).UNKNOWN_ERROR="UNKNOWN_ERROR",a.UNAVAILABLE_AUTHENTICATORS="UNAVAILABLE_AUTHENTICATORS",a.CANNOT_TRIGGER_WEBAUTHN_AUTHENTICATION="CANNOT_TRIGGER_WEBAUTHN_AUTHENTICATION",(i=t.OpenSessionWithWebAuthnAuthenticatorError||(t.OpenSessionWithWebAuthnAuthenticatorError={})).UNKNOWN_ERROR="UNKNOWN_ERROR",i.MP_MISSING_IN_SESSION_ERROR="MP_MISSING_IN_SESSION_ERROR",(o=t.DisableWebAuthnAuthenticationError||(t.DisableWebAuthnAuthenticationError={})).UNKNOWN_ERROR="UNKNOWN_ERROR",o.WEBAUTHN_SERVICE_DEACTIVATE_FAILED="WEBAUTHN_SERVICE_DEACTIVATE_FAILED",o.MISSING_LOGIN="MISSING_LOGIN",(n=t.RemoveWebAuthnAuthenticatorError||(t.RemoveWebAuthnAuthenticatorError={})).UNKNOWN_ERROR="UNKNOWN_ERROR",n.CANNOT_REMOVE_WEBAUTHN_AUTHENTICATOR="CANNOT_REMOVE_WEBAUTHN_AUTHENTICATOR",(r=t.StartWebAuthnAuthenticationError||(t.StartWebAuthnAuthenticationError={})).CANNOT_REFRESH_WEBAUTHN_AUTHENTICATORS="CANNOT_REFRESH_WEBAUTHN_AUTHENTICATORS",r.CANNOT_FETCH_WEBAUTHN_CHALLENGE="CANNOT_FETCH_WEBAUTHN_CHALLENGE"}},r={},n=function e(n){var o=r[n];if(void 0!==o)return o.exports;var i=r[n]={exports:{}};return t[n].call(i.exports,i,i.exports,e),i.exports}(14043);e.exports=n})()}},t={};function r(n){var o=t[n];if(void 0!==o)return o.exports;var i=t[n]={exports:{}};return e[n](i,i.exports,r),i.exports}(()=>{"use strict";var e=r(954);const t="dashlane-content-to-page",n="dashlane-content-ready";let o=0;const i=new Promise((e=>{const t=()=>{document.removeEventListener(n,t),e()};document.addEventListener(n,t)})),a=async(e,r)=>{var n;return"forward_webauthn_ready"!==(null===(n=document.getElementById("dashlane_webauthn"))||void 0===n?void 0:n.getAttribute("name"))&&await i,new Promise(((n,i)=>{const a=o+1;o=a;const u=e=>{const o=JSON.parse(e.detail);((e,t)=>"object"==typeof e&&null!==e&&"msgId"in e&&"number"==typeof e.msgId&&"response"in e&&t(e.response))(o,r)&&o.msgId===a&&(document.removeEventListener(t,u),n(o.response))};document.addEventListener(t,u);const s=new CustomEvent("dashlane-page-to-content",{detail:{msgId:a,message:e}});document.dispatchEvent(s)}))},u=Math.pow(10,6),s="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";function l(e){const t=e.length,r=[];for(let n=0;n<t;n+=3)r.push(s[e[n]>>2]),r.push(s[(3&e[n])<<4|e[n+1]>>4]),r.push(s[(15&e[n+1])<<2|e[n+2]>>6]),r.push(s[63&e[n+2]]);return r.join("")}function c(e){return function(e,t=u){const r=new Uint8Array(e),n=r.length,o=t%3,i=0===o?t:t+(3-o),a=Math.ceil(n/i);let s="",c=-1;for(;c++<a;){const e=c*i,t=c===a-1?n:(c+1)*i,o=l(r.slice(e,t));s=s.concat(o)}return n%3==2?s.substring(0,s.length-1)+"=":n%3==1?s.substring(0,s.length-2)+"==":s}(new Uint8Array(e)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=/g,"")}const A=new Uint8Array(256);for(let e=0;e<s.length;e++)A[s.charCodeAt(e)]=e;function E(e){const t=e.replace(/-/g,"+").replace(/_/g,"/"),r=(4-t.length%4)%4;return function(e){let t=.75*e.length;const r=e.length;let n,o,i,a,u,s=0;e.endsWith("=")&&(t--,"="===e[e.length-2]&&t--);const l=new ArrayBuffer(t),c=new Uint8Array(l);for(n=0;n<r;n+=4)o=A[e.charCodeAt(n)],i=A[e.charCodeAt(n+1)],a=A[e.charCodeAt(n+2)],u=A[e.charCodeAt(n+3)],c[s++]=o<<2|i>>4,c[s++]=(15&i)<<4|a>>2,c[s++]=(3&a)<<6|63&u;return l}(t.padEnd(t.length+r,"="))}function h(e){return"buffer"in e?e.buffer:e}var N;function b(t){return"object"==typeof t&&null!==t&&"function"in t&&t.function===e.WebAuthnCallTypes.CREATE&&"result"in t&&(0,e.isWebauthnResult)(t.result)}function R(t){return"object"==typeof t&&null!==t&&"function"in t&&t.function===e.WebAuthnCallTypes.GET&&"result"in t&&(0,e.isWebauthnResult)(t.result)}function _(e){return"object"==typeof e&&null!==e&&"function"in e&&e.function===N.IS_CONDITIONAL_UI_AVAILABLE&&"result"in e&&"boolean"==typeof e.result}!function(e){e.IS_CONDITIONAL_UI_AVAILABLE="IS_CONDITIONAL_UI_AVAILABLE"}(N||(N={}));const d={[e.WebauthnErrorName.NotSupportedError]:"The operation is not supported",[e.WebauthnErrorName.SecurityError]:"The operation is insecure",[e.WebauthnErrorName.NotAllowedError]:"The request is not allowed by the user agent or the platform in the current context, possibly because the user denied permission",[e.WebauthnErrorName.InvalidStateError]:"The object is in an invalid state",[e.WebauthnErrorName.UnknownError]:"The operation failed for an unknown transient reason (e.g. out of memory)"};class p{constructor(e){this._isFallbackForConditionalUI=(e,t)=>"conditional"===e&&"otherAuthenticator"===t.reason,this._originals=e}async create(t){const r=null==t?void 0:t.publicKey;if(r){const t=function(t){var r;return{function:e.WebAuthnCallTypes.CREATE,param:{...t,challenge:c(h(t.challenge)),excludeCredentials:(null!==(r=t.excludeCredentials)&&void 0!==r?r:[]).map((e=>({...e,id:c(h(e.id))}))),user:{...t.user,id:c(h(t.user.id))}}}}(r),n=await a(t,b);if(n.function===e.WebAuthnCallTypes.CREATE&&"useFallback"!==n.result.status){if("error"===n.result.status)throw new DOMException(d[n.result.errorName],n.result.errorName);return function(e){const t={clientDataJSON:E(e.clientDataJSON),attestationObject:E(e.attestationObject),getTransports:()=>e.transports,getPublicKeyAlgorithm:()=>e.publicKeyAlgorithm,getAuthenticatorData:()=>E(e.authenticatorData),getPublicKey:()=>E(e.publicKey)};return{...e,rawId:E(e.rawId),response:t,getClientExtensionResults:()=>{var t;return null!==(t=e.clientExtensionResults)&&void 0!==t?t:{}}}}(n.result.value)}}return this._originals.create(t)}async get(t){const r=null==t?void 0:t.mediation,n=null==t?void 0:t.publicKey;if(n){const o=function(t,r){var n;return{function:e.WebAuthnCallTypes.GET,mediation:r,param:{...t,challenge:c(h(t.challenge)),allowCredentials:(null!==(n=t.allowCredentials)&&void 0!==n?n:[]).map((e=>({...e,id:c(h(e.id))})))}}}(n,r),i=await a(o,R);if(i.function===e.WebAuthnCallTypes.GET){if("useFallback"!==i.result.status){if("error"===i.result.status)throw new DOMException(d[i.result.errorName],i.result.errorName);return function(e){const t={clientDataJSON:E(e.response.clientDataJSON),authenticatorData:E(e.response.authenticatorData),signature:E(e.response.signature),userHandle:e.response.userHandle?E(e.response.userHandle):null};return{...e,rawId:E(e.rawId),response:t,getClientExtensionResults:()=>{var t;return null!==(t=e.clientExtensionResults)&&void 0!==t?t:{}}}}(i.result.value)}this._isFallbackForConditionalUI(r,i.result)&&delete t.mediation}}return this._originals.get(t)}preventSilentAccess(){return this._originals.preventSilentAccess()}store(e){return this._originals.store(e)}}!function(){var e;const t=null===(e=window.PublicKeyCredential)||void 0===e?void 0:e.isConditionalMediationAvailable;window.PublicKeyCredential&&Object.defineProperty(window.PublicKeyCredential,"isConditionalMediationAvailable",{value:async()=>{const e={function:N.IS_CONDITIONAL_UI_AVAILABLE};return(await a(e,_)).result||(null==t?void 0:t())}});try{Object.defineProperty(navigator,"credentials",{value:new p(navigator.credentials)})}catch(e){}}()})()})();