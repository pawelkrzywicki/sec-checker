// Run the actual UI renderer against a small DOM substitute, without browser access.
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
class Element {
 constructor(tag='div'){this.tag=tag;this.children=[];this.attrs={};this.value='';this.textContent='';}
 append(...children){for(const child of children){if(child?.tag==='#fragment')this.children.push(...child.children);else this.children.push(child);}}
 replaceChildren(...children){this.children=[];this.append(...children);}
 setAttribute(key,value){this.attrs[key]=value;}
 getAttribute(key){return this.attrs[key];}
}
const nodes=new Map(),get=id=>{if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);};
const links=['html','csv','json'].map(kind=>{const e=new Element('a');e.setAttribute('href','/api/report/'+kind);return e;});
const document={getElementById:get,querySelector:()=>({content:'fixture-csrf'}),querySelectorAll:()=>links,createElement:tag=>new Element(tag),createTextNode:text=>({textContent:text}),createDocumentFragment:()=>new Element('#fragment')};
const context=vm.createContext({document,fetch:()=>new Promise(()=>{}),FormData:class{},setInterval:()=>0,clearInterval:()=>{}});
vm.runInContext(fs.readFileSync('static/app.js','utf8'),context);
const rows=[
 {host:'issue.example',needs_investigation:true,findings:[{severity:'High',title:'Outdated PHP',reason:'Version evidence',action:'Ask the operator',advisory:'https://www.php.net/archive/2026.php'}]},
 {host:'unknown.example',needs_investigation:false,php_unknown:true,findings:[]},
 {host:'incomplete.example',needs_investigation:false,incomplete:true,error:'Timeout',findings:[]}
].map(row=>({tls:'Validated',certificate:{},php:{status:'Unknown',evidence:''},...row}));
context.fixtures=rows;
vm.runInContext('lastResults=fixtures;drawResults();',context);
assert.equal(get('results').children.length,3);
get('filter-investigation').onclick();
assert.equal(get('results').children.length,1);
assert.equal(get('results').children[0].children[0].textContent,'issue.example');
assert.match(get('result-count').textContent,/Showing 1 of 3/);
assert.equal(get('filter-investigation').attrs['aria-pressed'],'true');
assert(links.every(link=>link.href.includes('filter=investigation')));
get('filter-incomplete').onclick();
assert.equal(get('results').children[0].children[0].textContent,'incomplete.example');
get('filter-all').onclick();
assert.equal(get('results').children.length,3);
// The investigation summary card activates the same filter.
get('summary').children[1].onclick();
assert.equal(get('results').children[0].children[0].textContent,'issue.example');
get('result-search').value='nomatch';get('result-search').oninput();
assert.equal(get('results').children[0].children[0].textContent,'No results match this filter.');
assert(links.every(link=>link.href.includes('q=nomatch')));
console.log('Result-view checks passed: filters, counts, summary button, search and matching export links.');
