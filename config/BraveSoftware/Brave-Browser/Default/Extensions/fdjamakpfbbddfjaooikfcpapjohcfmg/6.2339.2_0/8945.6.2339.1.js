"use strict";(globalThis.webpackChunk_dashlane_leeloo=globalThis.webpackChunk_dashlane_leeloo||[]).push([[8945],{182401:(e,t,a)=>{a.r(t),a.d(t,{NoteAddPanel:()=>v});var s=a(66941),i=a(947843),o=a(988799),n=a(696832),c=a(111768),r=a(592233),u=a(148038),d=a(537026),l=a(62429),S=a(635164),h=a(113181),g=a(38025),m=a(60043),p=a(885131),y=a(796446),N=a(234931),C=a(97242),b=a(507525),I=a(396119),T=a(919663),f=a(83541),w=a(925394);const{CONTENT:A,DOCUMENT_STORAGE:E}=N.SecureNoteTabs,F={noteCategories:{query:s.C.getNoteCategories}},k={strategies:F},v=(0,i.$)((0,o.i)((({lee:e,noteCategories:t})=>{var a,i;const{routes:o}=(0,m.Xo)(),N=(0,T.aV)(),F=(0,g.Y)(),{openPaywall:k}=(0,h.nL)(),v=(0,S.k6)(),[_,P]=(0,n.useState)(A),[D,O]=(0,n.useState)(!1),[U,V]=(0,n.useState)(!1),[Z,q]=(0,n.useState)([]),[z,R]=(0,n.useState)({category:"noCategory",type:"GRAY",spaceId:null!=(a=(0,d.B)(e.globalState))?a:"",secured:!1}),[B,G]=(0,n.useState)(!1),[L,M]=(0,n.useState)(!1),[X,Y]=(0,n.useState)(""),[x,H]=(0,n.useState)(""),K={attachments:Z.map(C.w),id:"",limitedPermissions:!1,content:X,title:x,...z};if((0,n.useEffect)((()=>{(0,l.Nc)(r.PageView.ItemSecureNoteCreate)}),[]),F.status!==u.rq.Success||!F?.data)return null;const Q=(0,f.n6)(f.Co.SecureNotes,F.data?.capabilities),W=()=>{(0,l.Nc)(r.PageView.ItemSecureNoteList),(0,I.z)(),(0,S.uX)(o.userSecureNotes)},$=()=>O(!0);return Q&&(k(f.qd.SecureNote),v.push("/secure-notes")),(0,c.tZ)(y.zI,{isViewingExistingItem:!1,itemHasBeenEdited:D,submitPending:U,onSubmit:async()=>{if(!U){V(!0);try{await(async()=>{await s.C.addSecureNote({...z,content:X,title:x,attachments:K.attachments}),q([])})()}catch{V(!1)}W()}},secondaryActions:_===E?[i||(i=(0,c.tZ)(b.d,{isQuotaReached:!1,isShared:!1,onFileUploadStarted:()=>{G(!0)},onFileUploadDone:async e=>{G(!1),e.success&&(await s.C.commitSecureFile({secureFileInfo:e.secureFileInfo}),q([...Z,e.secureFileInfo]),O(!0))},key:"uploadAction",dataType:"KWSecureNote"}))]:[],primaryActions:[],onNavigateOut:()=>{Z.forEach((async e=>{const{Id:t}=e;await s.C.deleteSecureFile({id:t})})),(0,I.z)(),q([]),W()},formId:"add_securenote_panel",header:(0,c.tZ)(w.h,{activeTab:_,backgroundColor:K.type,displayDocumentStorage:!0,displaySharedAccess:!1,setActiveTab:P,title:x,setTitle:e=>{$(),H(e)}})},(0,c.tZ)(p.T,{activeTab:_,data:K,content:X,setContent:Y,handleFileInfoDetached:e=>{q(Z.filter((t=>t.Id!==e)))},hasAttachment:!1,isAdmin:!1,isSecureNoteAttachmentEnabled:N,isShared:!1,isUploading:B,lee:e,noteCategories:t.items,onModifyData:$,saveSecureNoteOptions:R,isEditing:L,setIsEditing:M}))}),k),F)}}]);