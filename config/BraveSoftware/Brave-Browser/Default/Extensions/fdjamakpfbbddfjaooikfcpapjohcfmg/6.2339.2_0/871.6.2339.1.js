"use strict";(globalThis.webpackChunk_dashlane_leeloo=globalThis.webpackChunk_dashlane_leeloo||[]).push([[871,917],{542169:(e,a,t)=>{t.r(a),t.d(a,{DriverLicenseEditPanel:()=>D});var i=t(696832),r=t(382706),l=t(66941),n=t(343966),s=t(633075),d=t(157631),_=t(126750);const E={HEADER_DESCRIPTION:"webapp_id_edition_driverlicense_header_description",ALERT_DELETE:"webapp_id_edition_driverlicense_alert_delete",ALERT_EDIT:"webapp_id_edition_driverlicense_alert_edit",DIALOG_DELETE_TITLE:"webapp_id_edition_driverlicense_dialog_delete_title",COPY_SUCCESS:"webapp_id_copy_success_driverlicence_number"},c=e=>async()=>(await l.C.deleteDriverLicense({id:e})).success,o=(e,a)=>t=>{const i=(0,d.h)(a,t,n.j6),{expirationDate:r,issueDate:s}=i;return l.C.editDriverLicense({...i,expirationDate:r?Date.parse(r)/1e3:void 0,issueDate:s?Date.parse(s)/1e3:void 0,name:i.idName,id:e})},D=({listRoute:e,id:a,setDialogActive:t,lee:l,hasUnsavedData:n,setHasUnsavedData:d})=>a?i.createElement(_.y,{listRoute:e,id:`{${a}}`,setDialogActive:t,lee:l,hasUnsavedData:n,setHasUnsavedData:d,ID_TYPE:r.U.DriversLicense,I18N_KEYS:E,deleteItem:c,editItem:o},(({handleCopy:e,values:a})=>i.createElement(s.g,{variant:"edit",handleCopy:e,handleError:l.reportError,country:a.country}))):null},633075:(e,a,t)=>{t.d(a,{g:()=>D});var i,r,l=t(696832),n=t(201389),s=t(778089),d=t(803057),_=t(479055),E=t(754171),c=t(670570);const o={...E.k,STATE_LABEL:"webapp_id_form_field_label_state"},D=l.memo((({variant:e,handleCopy:a,handleError:t,country:E})=>{const{translate:D}=(0,n.Z)(),L=l.useRef(null);return l.useEffect("add"===e?()=>{const e=setTimeout((()=>{L.current?.focus()}),s.sc);return()=>clearTimeout(e)}:()=>{},[]),l.createElement(l.Fragment,null,l.createElement(c.YI,{name:"idName",label:D(o.NAME_LABEL),placeholder:D(o.NAME_PLACEHOLDER),ref:L}),l.createElement(c.G1,{name:"idNumber",label:D(o.ID_NUMBER_LABEL),placeholder:D(o.ID_NUMBER_PLACEHOLDER),handleCopy:"edit"===e?a:void 0}),l.createElement(c.Nn,{name:"issueDate",label:D(o.ISSUE_DATE_LABEL)}),l.createElement(c.Nn,{name:"expirationDate",label:D(_.a.has(E)?o.EXPIRATION_DATE_LABEL_UK:o.EXPIRATION_DATE_LABEL_US)}),l.createElement(c.ju,{countryFieldLabel:D(o.COUNTRY_LABEL),stateFieldLabel:D(o.STATE_LABEL),handleError:t}),i||(i=l.createElement(d.c,{height:24})),r||(r=l.createElement(c.A0,{name:"spaceId"})))}))}}]);