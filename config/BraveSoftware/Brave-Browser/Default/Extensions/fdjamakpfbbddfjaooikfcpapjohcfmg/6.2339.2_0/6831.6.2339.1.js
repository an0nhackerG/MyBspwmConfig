"use strict";(globalThis.webpackChunk_dashlane_leeloo=globalThis.webpackChunk_dashlane_leeloo||[]).push([[6831],{702394:(e,t,i)=>{i.d(t,{Z:()=>u,h:()=>l});var a=i(696832),n=i(111768),r=i(159515),s=i(151796),o=i(201389),c=i(177704);const l=({closeConfirmDeleteDialog:e,onDeleteConfirm:t,translations:i})=>{const{translate:r}=(0,o.Z)(),{confirmDeleteSubtitle:s,confirmDeleteTitle:l,confirmDeleteDismiss:u,confirmDeleteConfirm:d}=i;return a.createElement(n.Vq,{title:l,onClose:e,isOpen:!0,dialogClassName:c.Ht,closeActionLabel:r("_common_dialog_dismiss_button"),isDestructive:!0,actions:{primary:{children:d,onClick:t,id:"deletion-dialog-confirm-button"},secondary:{children:u,onClick:e,autoFocus:!0,id:"deletion-dialog-dismiss-button"}}},s)},u=({reason:e,translations:t,goToSharingAccess:i,closeCantDeleteDialog:c})=>{const{translate:l}=(0,o.Z)(),u=((e,t)=>{const{groupSharingTitle:i,lastAdminTitle:a,genericErrorTitle:n}=e;switch(t){case r.J.LastAdmin:return a;case r.J.GroupSharing:return i;case r.J.Generic:return n;default:return(0,s.U)(t)}})(t,e),d=((e,t)=>{const{groupSharingSubtitle:i,lastAdminSubtitle:a,genericErrorSubtitle:n}=e;switch(t){case r.J.LastAdmin:return a;case r.J.GroupSharing:return i;case r.J.Generic:return n;default:return(0,s.U)(t)}})(t,e);return a.createElement(n.Vq,{isOpen:!0,onClose:c,title:null!=u?u:"",closeActionLabel:l("_common_dialog_dismiss_button"),actions:e===r.J.LastAdmin?{primary:{children:t.lastAdminActionLabel,onClick:i}}:void 0},d)}},372814:(e,t,i)=>{i.d(t,{N:()=>o});var a=i(696832),n=i(592233),r=i(201389),s=i(508461);const o=({item:e,getSharing:t})=>{const{translate:i}=(0,r.Z)();if(!(e=>e&&(!e.sharingStatus.isShared||"admin"===e.sharingStatus.permission)&&!e.attachments.length)(e))return null;const o=t(e.id);return a.createElement(s.Z,{tooltipPlacement:"top-start",sharing:o,text:i("webapp_sharing_invite_share"),origin:n.Origin.ItemDetailView})}},159515:(e,t,i)=>{let a;i.d(t,{J:()=>a}),function(e){e[e.LastAdmin=0]="LastAdmin",e[e.GroupSharing=1]="GroupSharing",e[e.Generic=2]="Generic"}(a||(a={}))},548511:(e,t,i)=>{i.r(t),i.d(t,{NoteEditPanel:()=>F});var a=i(66941),n=i(947843),r=i(988799),s=i(696832),o=i(238250),c=i(592233),l=i(62429),u=i(201389),d=i(635164),m=i(60043),g=i(880706),S=i(234931),h=i(159515),p=i(372814),_=i(702394),b=i(796446),C=i(793071),E=i(885131),f=i(889483),D=i(97242),A=i(507525),y=i(396119),N=i(919663),w=i(925394);const{CONTENT:I,DOCUMENT_STORAGE:T,MORE_OPTIONS:v,SHARED_ACCESS:G}=S.SecureNoteTabs,O=e=>(0,C.A1)(e),L=(0,f.DP)((({lee:e,location:t,note:i,noteCategories:n})=>{var r;const{translate:C}=(0,u.Z)(),{routes:f}=(0,m.Xo)(),L=(0,N.aV)(),[J,k]=(0,s.useState)(I),[P,F]=(0,s.useState)(!1),[R]=(0,s.useState)(null),[V,U]=(0,s.useState)(!1),[X,Z]=(0,s.useState)(null),[H,M]=(0,s.useState)(!1),[q,B]=(0,s.useState)(!1),[x,z]=(0,s.useState)(!1),[$,K]=(0,s.useState)(!1),[Q,W]=(0,s.useState)((()=>i.content)),[j,Y]=(0,s.useState)((()=>i.title)),ee=s.useCallback((()=>!i&&((0,d.uX)(f.userSecureNotes),!0)),[i,f.userSecureNotes]);if(s.useEffect((()=>{ee()||(0,l.Nc)(c.PageView.ItemSecureNoteDetails)}),[ee]),s.useEffect((()=>{ee()}),[ee,i]),!i)return null;const te=()=>{(0,y.z)(),t?.state?.entity?(0,g.d)({routes:f,location:t}):((0,l.Nc)(c.PageView.ItemSecureNoteList),(0,d.uX)(f.userSecureNotes))},ie=async(e=!0)=>{var t;B(!0);const n=null!=R?R:{spaceId:null!=(t=i.spaceId)?t:""};await a.C.updateSecureNote({content:Q,title:j,id:i.id,attachments:[...i.attachments],...n}),B(!1),e?te():(K(!1),F(!1))},ae=()=>{z(!0)},ne=async e=>{z(!1),e.success&&(await a.C.commitSecureFile({secureFileInfo:e.secureFileInfo}),i.attachments.push((0,D.w)(e.secureFileInfo)),ie(!1))},re=()=>Z(null),se=e=>Z({reason:e}),oe=()=>F(!0),ce=i?.sharingStatus.isShared,le=L||i.attachments.length>0,ue=[I,v];ce?ue.push(G):le&&ue.push(T);const de={confirmDeleteConfirm:C("webapp_secure_notes_edition_delete_confirm"),confirmDeleteDismiss:C("webapp_credential_edition_delete_dismiss"),confirmDeleteSubtitle:C("webapp_credential_edition_confirm_delete_subtitle"),confirmDeleteTitle:C("webapp_secure_notes_edition_delete_title"),lastAdminActionLabel:C("webapp_credential_edition_change_permissions"),lastAdminTitle:C("webapp_credential_edition_last_admin_title"),lastAdminSubtitle:C("webapp_credential_edition_last_admin_subtitle"),groupSharingTitle:C("webapp_secure_notes_edition_group_sharing_title"),groupSharingSubtitle:C("webapp_credential_edition_group_sharing_subtitle"),genericErrorTitle:"webapp_account_recovery_generic_error_title",genericErrorSubtitle:"webapp_account_recovery_generic_error_subtitle"},me={attachments:i.attachments,category:i.category?i.category.id:"noCategory",content:i.content,id:i.id,limitedPermissions:i.sharingStatus.isShared&&"limited"===i.sharingStatus.permission,secured:i.secured,spaceId:i.spaceId,title:i.title,type:i.color},ge=i.sharingStatus.isShared?i.sharingStatus.recipientsCount:0;return s.createElement(b.zI,{isViewingExistingItem:!0,itemHasBeenEdited:P,onSubmit:()=>{ie()},submitPending:q,secondaryActions:(()=>{switch(J){case I:return[r||(r=s.createElement(p.N,{item:i,getSharing:O,key:"shareaction"}))];case T:return[s.createElement(A.d,{isQuotaReached:!1,onFileUploadStarted:ae,onFileUploadDone:ne,isShared:i?.sharingStatus.isShared,itemId:i.id,key:"uploadAction",dataType:"KWSecureNote"})];default:return[]}})(),onNavigateOut:te,onClickDelete:()=>{const{sharingStatus:e}=i;if(e.isShared){if(e.groupSharing)return void se(h.J.GroupSharing);if(e.lastAdmin)return void se(h.J.LastAdmin)}U(!0)},ignoreCloseOnEscape:V||H,isSomeDialogOpen:!!X,formId:"edit_securenote_panel",header:s.createElement(w.h,{activeTab:J,backgroundColor:me.type,displayDocumentStorage:ue.includes(T),displaySharedAccess:ue.includes(G),recipientsCount:ge,setActiveTab:k,disabled:me.limitedPermissions,title:j,setTitle:e=>{oe(),Y(e)}})},s.createElement(E.T,{activeTab:J,data:me,content:Q,setContent:W,handleFileInfoDetached:e=>{i.attachments=i.attachments.filter((t=>t.id!==e)),ie(!1)},hasAttachment:i.attachments.length>0,isAdmin:i.sharingStatus.isShared&&"admin"===i.sharingStatus.permission,isSecureNoteAttachmentEnabled:L,isShared:i.sharingStatus.isShared,isUploading:x,isEditing:$,setIsEditing:K,lee:e,noteCategories:n.items,onModifyData:oe,onModalDisplayStateChange:M,saveSecureNoteOptions:e=>{const{category:t,spaceId:n,type:r,secured:s}=e;a.C.updateSecureNote({id:i.id,spaceId:null!=n?n:"",type:r,category:t,secured:s})}}),V&&s.createElement(_.h,{closeConfirmDeleteDialog:()=>U(!1),onDeleteConfirm:async()=>{i.attachments.forEach((async e=>{const{id:t}=e;await a.C.deleteSecureFile({id:t})}));const e=await a.C.deleteSecureNote({id:i.id});e.success?(0,d.uX)(f.userSecureNotes):e.error.code===o.DeleteSecureNoteErrorCode.LEAVE_SHARING_FORBIDDEN_GROUP_ITEM?se(h.J.GroupSharing):e.error.code===o.DeleteSecureNoteErrorCode.LEAVE_SHARING_FORBIDDEN_LAST_ADMIN?se(h.J.LastAdmin):se(h.J.Generic)},translations:de}),X&&s.createElement(_.Z,{reason:X.reason,translations:de,goToSharingAccess:()=>{re(),k(S.SecureNoteTabs.SHARED_ACCESS)},closeCantDeleteDialog:re}))})),J=e=>{if(!e.match.params)throw new Error("missing route `params`");return`{${e.match.params.uuid}}`},k={note:{live:a.C.liveNote,liveParam:J,query:a.C.getNote,queryParam:J},noteCategories:{query:a.C.getNoteCategories}},P={strategies:k},F=(0,n.$)((0,r.i)(L,P),k)},880706:(e,t,i)=>{i.d(t,{d:()=>r});var a=i(528144),n=i(635164);const r=({routes:e,location:t})=>{t?.state?.entity?(0,a.yy)(t?.state?.entity)?(0,n.uX)(e.userSharingGroupInfo(t?.state?.entity?.groupId)):(0,n.uX)(e.userSharingUserInfo(t?.state?.entity?.alias)):(0,n.uX)(e.userSharingCenter)}}}]);