'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const source=fs.readFileSync(require.resolve('../src/i18n.js'),'utf8');
function load(navigator,saved,blocked=false){
  const values=new Map(saved===undefined?[]:[['pcaproom-easy.language.v1',saved]]);
  const context=vm.createContext({...navigator===undefined?{}:{navigator},localStorage:{getItem(key){if(blocked)throw Error('denied');return values.get(key)??null;},setItem(key,value){if(blocked)throw Error('denied');values.set(key,value);}}});
  vm.runInContext(source,context);
  return {i18n:context.PcapI18n,values};
}
test('primary browser preference chooses Japanese or English, with language fallback',()=>{
  for(const [navigator,expected]of [
    [{languages:['ja-JP'],language:'en-US'},'ja'],
    [{languages:['JA-jp'],language:'en'},'ja'],
    [{languages:['th-TH'],language:'ja'},'en'],
    [{languages:['fr-FR','ja'],language:'ja'},'en'],
    [{languages:['en-US','ja'],language:'ja'},'en'],
    [{languages:[null,' ','ja-JP'],language:'en'},'ja'],
    [{languages:[],language:'ja-JP'},'ja'],
    [{language:'en-GB'},'en'],
    [{languages:'en',language:'ja-JP'},'ja'],
    [{language:42},'en'],[{},'en'],[undefined,'en'],
    [{get languages(){throw Error('denied');},language:'ja'},'ja'],
    [{get languages(){throw Error('denied');},get language(){throw Error('denied');}},'en'],
  ])assert.equal(load(navigator).i18n.locale,expected);
});
test('valid saved choices override the browser, invalid choices use its default',()=>{
  for(const language of ['ja','en'])for(const saved of ['ja','en'])assert.equal(load({language},saved).i18n.locale,saved);
  for(const invalid of [undefined,'','th','invalid'])assert.equal(load({language:'ja-JP'},invalid).i18n.locale,'ja');
  const {i18n,values}=load({language:'fr-FR'});
  i18n.setLocale('ja');assert.equal(values.get('pcaproom-easy.language.v1'),'ja');
  assert.equal(load({language:'fr-FR'},values.get('pcaproom-easy.language.v1')).i18n.locale,'ja');
});
test('storage restrictions leave browser defaults and in-session language switching usable',()=>{
  for(const [language,expected]of [['ja-JP','ja'],['th-TH','en']]){
    const {i18n}=load({language},'ja',true);
    assert.equal(i18n.locale,expected);
    i18n.setLocale('en');assert.equal(i18n.locale,'en');i18n.setLocale('ja');assert.equal(i18n.locale,'ja');
  }
});
