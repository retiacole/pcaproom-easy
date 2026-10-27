'use strict';
module.exports=function validateTranslations(data,en){
 const errors=[],japanese=/[\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Han}]/u;
 const text=(s,key)=>{if(typeof s!=='string'||!s.trim()||japanese.test(s))errors.push(`Missing/incomplete English: ${key}`);};
 for(const [kind,fields]of [['chapters',['title','subtitle']],['captures',['title','description']],['lessons',['title','intro','mission','explanation']]]){
  const canonical=data[kind],translations=en[kind];
  for(const item of canonical){const t=translations[item.id];if(!t){errors.push(`Missing English ${kind}: ${item.id}`);continue;}
   for(const field of fields)text(t[field],`${item.id}.${field}`);
   const allowed=new Set([...fields,...(kind==='lessons'?['hints','tasks','referenceCards']:[])]);
   for(const key of Object.keys(t))if(!allowed.has(key))errors.push(`English must not override ${item.id}.${key}`);
   if(kind==='lessons'){
    if(item.referenceCards){
     if(t.referenceCards?.length!==item.referenceCards.length)errors.push(`English reference count: ${item.id}`);
     item.referenceCards.forEach((card,i)=>{const tr=t.referenceCards?.[i]||{};
      text(tr.title,`${item.id}.referenceCards.${i}.title`);text(tr.body,`${item.id}.referenceCards.${i}.body`);
      for(const key of Object.keys(tr))if(!['title','body'].includes(key))errors.push(`English must not override reference ${item.id}.${key}`);
     });
    }

    if(t.hints?.length!==3)errors.push(`Three English hints required: ${item.id}`);
    t.hints?.forEach((h,i)=>text(h,`${item.id}.hints.${i}`));
    if(t.tasks?.length!==item.tasks.length)errors.push(`English task count: ${item.id}`);
    item.tasks.forEach((task,i)=>{const tr=t.tasks?.[i];if(!tr){errors.push(`Missing English task: ${item.id}/${task.id}`);return;}
     for(const key of Object.keys(tr))if(!['prompt','why','options'].includes(key))errors.push(`English must not override ${item.id}/${task.id}.${key}`);
     text(tr.prompt,`${item.id}/${task.id}.prompt`);text(tr.why,`${item.id}/${task.id}.why`);
     if(task.options){for(const o of task.options)text(tr.options?.[o.value],`${item.id}/${task.id}.${o.value}`);if(Object.keys(tr.options||{}).length!==task.options.length)errors.push(`English option count: ${item.id}/${task.id}`);}
    });
   }
  }
  for(const id of Object.keys(translations))if(!canonical.some(item=>item.id===id))errors.push(`Unknown English ${kind}: ${id}`);
 }
 if(en.glossary?.length!==data.glossary.length)errors.push('English glossary count');
 en.glossary?.forEach((g,i)=>{text(g.term,`glossary.${i}.term`);text(g.description,`glossary.${i}.description`);});
 return errors;
};
