"use strict";(globalThis.webpackChunk_dashlane_leeloo=globalThis.webpackChunk_dashlane_leeloo||[]).push([[4942],{619733:(e,t,s)=>{s.d(t,{N:()=>l});var a=s(696832),n=s(383849),i=s.n(n);const l=({disableHover:e=!1,...t})=>{const[s,n]=a.useState(!1),{children:[l,...r]=[]}=t;return a.createElement("div",{className:"buttonsContainer--TiPIoxROXR",onMouseEnter:()=>n(!0),onMouseLeave:()=>n(!1)},l,t.enabled&&a.createElement("span",{className:i()("buttons--p98QFrEo3f",{"visible--aWYlZRshE_":e||s})},r))}},313661:(e,t,s)=>{s.d(t,{Z:()=>_});var a=s(696832),n=s(554712),i=s(383849),l=s.n(i),r=s(526849),o=s(769183),d=s(317894),p=s.n(d),c=s(111768),u=s(654),h=s(83126);const m=e=>{navigator.clipboard.writeText(e.replaceAll(" ",""))};class _ extends a.Component{constructor(e){super(e),this.field=void 0,this.handleChange=e=>{this.setState({selectionRangeStart:e.target.selectionStart,selectionRangeEnd:e.target.selectionEnd}),this.props.onChange&&this.props.onChange(e)},this.state={fieldHtmlId:(0,o.Z)(),selectionRangeStart:null,selectionRangeEnd:null}}componentDidUpdate(){null!==this.state.selectionRangeStart&&null!==this.state.selectionRangeEnd&&this.field.setSelectionRange(this.state.selectionRangeStart,this.state.selectionRangeEnd)}shouldComponentUpdate(e,t){return!((0,r.equals)(this.props.value,e.value)&&(0,r.equals)(this.props.error,e.error)&&(0,r.equals)(this.props.mask,e.mask)&&(0,r.equals)(this.props.label,e.label)&&(0,r.equals)(this.state.selectionRangeStart,t.selectionRangeStart)&&(0,r.equals)(this.state.selectionRangeEnd,t.selectionRangeEnd))}getValue(){return this.field.value}focus(){this.field.focus()}getTextarea(){var e;return(0,c.tZ)(n.Z,{inputRef:e=>{this.field=e},id:this.state.fieldHtmlId,disabled:this.props.disabled,value:null!=(e=this.props.value)?e:"",name:this.props.name,"data-name":this.props.dataName,sx:{borderColor:this.props.error&&"ds.border.danger.standard.idle"},className:h.Z.textarea,placeholder:this.props.placeholder,onBlur:this.props.handleFieldBlur,onKeyDown:this.props.onFieldKeyDown,onChange:this.handleChange})}getInput(){var e;const t={onBlur:this.props.handleFieldBlur,onChange:this.handleChange,disabled:this.props.disabled,readOnly:this.props.readOnly,value:null!=(e=this.props.value)?e:""},s={ref:e=>{this.field=e},id:this.state.fieldHtmlId,autoComplete:"off",className:l()(h.Z.input,{[h.Z.error]:Boolean(this.props.error)}),sx:{...this.props.error&&{"::placeholder":{color:"ds.text.danger.quiet"},minWidth:"fit-content"},border:"1px solid",borderColor:this.props.error?"ds.border.danger.standard.idle":"transparent"},name:this.props.name,"data-name":this.props.dataName,type:this.props.type||"text",placeholder:this.props.placeholder,onKeyDown:this.props.onFieldKeyDown};return this.props.mask?(0,c.tZ)(p(),{...t,...this.props.maskProps,mask:this.props.mask,onCopy:()=>m(t.value),onCut:()=>m(t.value)},(e=>(0,c.tZ)("input",{...s,...e}))):(0,c.tZ)("div",{className:h.Z.inputRow},(0,c.tZ)("input",{...s,...t}),(0,c.tZ)("div",{hidden:!this.props.error||"string"!=typeof this.props.error,sx:{color:"ds.text.danger.quiet"},className:h.Z.errorMessage},this.props.error))}render(){const e="password"!==this.props.type?this.props.value||this.props.placeholder:"";return(0,c.tZ)("div",{className:l()(h.Z.container,this.props.multiLine?h.Z.containerMultiLine:null)},this.props.label&&(0,c.tZ)("label",{className:h.Z.label,sx:{color:"ds.text.neutral.catchy"},htmlFor:this.state.fieldHtmlId},(0,c.tZ)("span",{className:h.Z.text,title:this.props.label},this.props.label)),(0,c.tZ)(u.Z,{tooltipText:e,className:l()(h.Z.value,{[h.Z.placeholder]:!this.props.value,[h.Z.multiline]:this.props.multiLine})},this.props.multiLine?this.getTextarea():this.getInput()))}}_.defaultProps={maskProps:{maskChar:""}}},449354:(e,t,s)=>{s.d(t,{d:()=>c}),s(696832);var a,n=s(111768),i=s(5727),l=s(441217),r=s(619733),o=s(313661),d=s(201389);const p="webapp_credential_edition_field_website_action_goto",c=({url:e,hasUrlError:t,editViewButtonEnabled:s,limitedPermissions:c=!1,handleChange:u,handleGoToWebsite:h})=>{const{translate:m}=(0,d.Z)();return(0,i.tZ)(r.N,{enabled:s,disableHover:!0},(0,i.tZ)(o.Z,{label:m("webapp_credential_edition_field_website"),placeholder:m("webapp_credential_edition_field_placeholder_no_url"),dataName:"url",value:e,error:t,readOnly:c,onChange:u}),(0,i.tZ)(l.ua7,{placement:"top",content:m(p)},(0,i.tZ)(n.zx,{mood:"neutral",intensity:"supershy",type:"button",onClick:h,sx:{border:"none",minWidth:"fit-content",padding:"10px"},role:"link","aria-label":m(p)},a||(a=(0,i.tZ)(l.RTC,null)))))}},702394:(e,t,s)=>{s.d(t,{Z:()=>p,h:()=>d});var a=s(696832),n=s(111768),i=s(159515),l=s(151796),r=s(201389),o=s(177704);const d=({closeConfirmDeleteDialog:e,onDeleteConfirm:t,translations:s})=>{const{translate:i}=(0,r.Z)(),{confirmDeleteSubtitle:l,confirmDeleteTitle:d,confirmDeleteDismiss:p,confirmDeleteConfirm:c}=s;return a.createElement(n.Vq,{title:d,onClose:e,isOpen:!0,dialogClassName:o.Ht,closeActionLabel:i("_common_dialog_dismiss_button"),isDestructive:!0,actions:{primary:{children:c,onClick:t,id:"deletion-dialog-confirm-button"},secondary:{children:p,onClick:e,autoFocus:!0,id:"deletion-dialog-dismiss-button"}}},l)},p=({reason:e,translations:t,goToSharingAccess:s,closeCantDeleteDialog:o})=>{const{translate:d}=(0,r.Z)(),p=((e,t)=>{const{groupSharingTitle:s,lastAdminTitle:a,genericErrorTitle:n}=e;switch(t){case i.J.LastAdmin:return a;case i.J.GroupSharing:return s;case i.J.Generic:return n;default:return(0,l.U)(t)}})(t,e),c=((e,t)=>{const{groupSharingSubtitle:s,lastAdminSubtitle:a,genericErrorSubtitle:n}=e;switch(t){case i.J.LastAdmin:return a;case i.J.GroupSharing:return s;case i.J.Generic:return n;default:return(0,l.U)(t)}})(t,e);return a.createElement(n.Vq,{isOpen:!0,onClose:o,title:null!=p?p:"",closeActionLabel:d("_common_dialog_dismiss_button"),actions:e===i.J.LastAdmin?{primary:{children:t.lastAdminActionLabel,onClick:s}}:void 0},c)}},159515:(e,t,s)=>{let a;s.d(t,{J:()=>a}),function(e){e[e.LastAdmin=0]="LastAdmin",e[e.GroupSharing=1]="GroupSharing",e[e.Generic=2]="Generic"}(a||(a={}))},794942:(e,t,s)=>{s.r(t),s.d(t,{Connected:()=>D});var a=s(696832),n=s(448430),i=s(382706),l=s(799852),r=s(111768),o=s(441217),d=s(796446),p=s(22393),c=s(635164),u=s(201389),h=s(66941),m=s(60043),_=s(787268),g=s(702394),b=s(592233),f=s(164718),y=s(313661),k=s(62429),Z=s(449354),C=s(447725),w=s(839434);const v=({passkeyContent:e,signalEditedValues:t})=>{const{translate:s}=(0,u.Z)(),{userDisplayName:n,rpId:i,itemName:l,note:o,spaceId:d,id:p}=e;(0,a.useEffect)((()=>{(0,k.Nc)(b.PageView.ItemPasskeyDetails)}),[]);const c=s=>a=>{const n="string"==typeof a?a:a.target.value;t({...e,[s]:n})};return(0,r.tZ)(a.Fragment,null,(0,r.tZ)("div",{sx:{marginBottom:"32px"}},(0,r.tZ)(y.Z,{key:"passkeyUsername",value:n,label:s("webapp_passkey_edition_field_username"),placeholder:s("webapp_passkey_edition_field_username_placeholder")}),(0,r.tZ)(Z.d,{url:i,hasUrlError:!1,editViewButtonEnabled:!0,limitedPermissions:!1,handleChange:(e,t="")=>{if(e instanceof Event&&t)throw new Error("handleChange was called with both a ChangeEvent and key.")},handleGoToWebsite:()=>{(0,k.Kz)(new b.UserOpenExternalVaultItemLinkEvent({itemId:p,itemType:b.ItemTypeWithLink.Passkey,domainType:b.DomainType.Web})),(0,C.Yo)(new f.Y(i).getUrlWithFallbackHttpsProtocol())}})),(0,r.tZ)(y.Z,{key:"passkeyItemName",value:null!=l?l:n,onChange:c("itemName"),label:s("webapp_passkey_edition_field_item_name"),placeholder:s("webapp_passkey_edition_field_item_name_placeholder")}),(0,r.tZ)(w.M,{spaceId:d,labelSx:w.e,onChange:e=>c("spaceId")(e)}),(0,r.tZ)(y.Z,{label:s("webapp_passkey_edition_field_notes"),placeholder:s("webapp_passkey_edition_field_placeholder_no_notes"),dataName:"note",value:o,onChange:c("note"),multiLine:!0}))};var x;const E="_common_generic_error",R=({item:e})=>{var t;const{routes:s}=(0,m.Xo)(),{translate:n}=(0,u.Z)(),{openDialog:i,closeDialog:l}=(0,p.R)(),b=(0,c.k6)(),f=(0,_.V)(),[y,k]=a.useState(e),[Z,C]=a.useState(!1),[w,R]=a.useState(!1),D=()=>{l(),b.push(s.userPasskeys)},S={confirmDeleteConfirm:n("webapp_passkey_edition_delete_confirm"),confirmDeleteDismiss:n("webapp_passkey_edition_delete_dismiss"),confirmDeleteSubtitle:n("webapp_passkey_edition_delete_text"),confirmDeleteTitle:n("webapp_passkey_edition_delete_header")},I=async()=>{if(e)if((await h.C.deletePasskey({id:e.id})).success){const t=n("webapp_passkey_edition_name_delete_alert",{passkey:e.rpName});f.showAlert(t,o.BLW.SUBTLE)}else f.showAlert(n(E),o.BLW.ERROR);D()},N=a.useRef({}),L=a.useCallback((t=>{Object.entries(t).forEach((([t,s])=>{e[t]!==s?N.current[t]=s:delete N.current[t]})),R(Object.keys(N.current).length>0),k(t)}),[e]);return(0,r.tZ)(d.zI,{itemHasBeenEdited:w,isViewingExistingItem:!0,onNavigateOut:D,onClickDelete:()=>{i(t||(t=(0,r.tZ)(g.h,{closeConfirmDeleteDialog:l,onDeleteConfirm:I,translations:S})))},onSubmit:async()=>{if(!Z){C(!0);try{if(!0===(await h.C.updatePasskey({id:e.id,...N.current})).success){const t=n("webapp_passkey_edition_name_update_alert",{passkey:e.rpName});f.showAlert(t,o.BLW.SUCCESS),b.push(s.userPasskeys)}else C(!1)}catch(e){C(!1),f.showAlert(n(E),o.BLW.ERROR)}}},formId:"edit_passkey_panel",header:(0,r.tZ)(d.V9,{icon:(0,r.tZ)("div",{sx:{display:"flex",alignItems:"center",justifyContent:"center",width:"147px",height:"98px"}},x||(x=(0,r.tZ)(r.JO,{name:"PasskeyOutlined",size:"xlarge",color:"white"}))),iconBackgroundColor:"ds.container.expressive.brand.catchy.active",title:e.rpName})},(0,r.tZ)(v,{itemId:e.id,passkeyContent:y,signalEditedValues:L}))},D=e=>{const{data:t}=(0,l.k)(n.L,"query",{vaultItemTypes:[i.U.Passkey],ids:[`{${e.match.params.uuid}}`]});return t?.passkeysResult.items.length?a.createElement(R,{...e,item:t.passkeysResult.items[0]}):null}},83126:(e,t,s)=>{s.d(t,{Z:()=>a});const a={container:"container--Qypu77vxOn",containerMultiLine:"containerMultiLine--ncWYFwQEnR",_field:"_field--KII5X4xmLN",input:"input--Iq10hxAz32 _field--KII5X4xmLN",inputRow:"inputRow--gdD_j5S1R8",textarea:"textarea--VpIWTZemV2 _field--KII5X4xmLN",label:"label--Ww_r49kt_J",text:"text--oXyCzpUMwG",value:"value--aD7nWEqBIq",multiline:"multiline--fdPM1KFHPT"}}}]);