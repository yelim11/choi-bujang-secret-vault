import { respond } from './respond.mjs';

export async function afterRun({root,fixture,result}){
  return respond({root,fixture,result});
}
