"use strict";(globalThis.webpackChunk_dashlane_leeloo=globalThis.webpackChunk_dashlane_leeloo||[]).push([[8182],{702394:(e,t,n)=>{n.d(t,{Z:()=>d,h:()=>c});var i=n(696832),r=n(111768),a=n(159515),o=n(151796),l=n(201389),s=n(177704);const c=({closeConfirmDeleteDialog:e,onDeleteConfirm:t,translations:n})=>{const{translate:a}=(0,l.Z)(),{confirmDeleteSubtitle:o,confirmDeleteTitle:c,confirmDeleteDismiss:d,confirmDeleteConfirm:u}=n;return i.createElement(r.Vq,{title:c,onClose:e,isOpen:!0,dialogClassName:s.Ht,closeActionLabel:a("_common_dialog_dismiss_button"),isDestructive:!0,actions:{primary:{children:u,onClick:t,id:"deletion-dialog-confirm-button"},secondary:{children:d,onClick:e,autoFocus:!0,id:"deletion-dialog-dismiss-button"}}},o)},d=({reason:e,translations:t,goToSharingAccess:n,closeCantDeleteDialog:s})=>{const{translate:c}=(0,l.Z)(),d=((e,t)=>{const{groupSharingTitle:n,lastAdminTitle:i,genericErrorTitle:r}=e;switch(t){case a.J.LastAdmin:return i;case a.J.GroupSharing:return n;case a.J.Generic:return r;default:return(0,o.U)(t)}})(t,e),u=((e,t)=>{const{groupSharingSubtitle:n,lastAdminSubtitle:i,genericErrorSubtitle:r}=e;switch(t){case a.J.LastAdmin:return i;case a.J.GroupSharing:return n;case a.J.Generic:return r;default:return(0,o.U)(t)}})(t,e);return i.createElement(r.Vq,{isOpen:!0,onClose:s,title:null!=d?d:"",closeActionLabel:c("_common_dialog_dismiss_button"),actions:e===a.J.LastAdmin?{primary:{children:t.lastAdminActionLabel,onClick:n}}:void 0},u)}},159515:(e,t,n)=>{let i;n.d(t,{J:()=>i}),function(e){e[e.LastAdmin=0]="LastAdmin",e[e.GroupSharing=1]="GroupSharing",e[e.Generic=2]="Generic"}(i||(i={}))},559023:(e,t,n)=>{n.r(t),n.d(t,{Connected:()=>A});var i=n(696832),r=n(799852),a=n(448430),o=n(382706),l=n(526849),s=n(453576),c=n(592233),d=n(441217),u=n(66941),m=n(62429),_=n(201389),p=n(635164),g=n(60043),f=n(796446),h=n(487322),b=n(702394),C=n(635978);const D=["building","city","digitCode","door","floor","id","localeFormat","receiver","spaceId","stairs","state","stateNumber","streetName","streetNumber","zipCode"],S=({lee:e,match:t,item:n})=>{var r,a,o;const S=(0,i.createRef)(),[A,E]=i.useState(!1),[k,w]=i.useState(!1),{translate:v}=(0,_.Z)(),{routes:I}=(0,g.Xo)();i.useEffect((()=>{(0,m.Nc)(c.PageView.ItemAddressDetails)}),[]);const y=()=>{(0,m.Nc)(c.PageView.ItemPersonalInfoList),(0,p.uX)(I.userPersonalInfo)},N=()=>{y()},T=Boolean(t.params?.uuid),L=null!=(r=n?.itemName)?r:"",P=v("webapp_personal_info_edition_header_address_description"),V=i.createElement(h.ZP,{iconSize:h.Jh.headerEditPanelIcon,iconType:h.Tu.address}),G={confirmDeleteConfirm:v("webapp_personal_info_edition_delete_confirm"),confirmDeleteDismiss:v("webapp_personal_info_edition_delete_dismiss"),confirmDeleteSubtitle:v("webapp_personal_info_edition_delete_subtitle"),confirmDeleteTitle:v("webapp_personal_info_edition_delete_title_address")},J=s.Country[e.globalState.locale.country],F=n?{...(0,l.pick)(D,n),addressName:n.itemName,linkedPhone:n.linkedPhoneId,localeFormat:null!=(a=null!=(o=n?.localeFormat)?o:J)?a:s.Country.US}:null;return i.createElement(f.zI,{isViewingExistingItem:T,itemHasBeenEdited:A,onNavigateOut:N,onSubmit:async()=>{if(null==(e=S.current?.isFormValid())||!e||!n)return;var e;const t=null!=(i=S.current?.getValues())?i:null;var i;const r={kwType:"KWAddress",origin:s.SaveOrigin.MANUAL,content:{...t,addressFull:t?.streetName,id:n.id}};await u.C.savePersonalDataItem(r),N()},onClickDelete:()=>w(!0),ignoreCloseOnEscape:k,formId:"edit_address_panel",header:i.createElement(f.V9,{icon:V,iconBackgroundColor:d.colors.dashGreen00,title:L,titleDescription:P})},F?i.createElement(C.k,{lee:e,currentValues:F,signalEditedValues:()=>E(!0),ref:S}):null,k?i.createElement(b.h,{closeConfirmDeleteDialog:()=>w(!1),onDeleteConfirm:()=>{n&&(u.C.removePersonalDataItem({id:n.id}),y())},translations:G}):null)},A=e=>{const t=(0,r.k)(a.L,"query",{vaultItemTypes:[o.U.Address],ids:[`{${e.match.params.uuid}}`]});return i.createElement(S,{...e,item:t.data?.addressesResult.items[0]})}}}]);