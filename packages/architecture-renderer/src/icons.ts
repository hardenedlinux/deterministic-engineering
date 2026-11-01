import { LibraryBig, SlidersHorizontal, ScanLine, Network, FileText, GitBranch, ShieldCheck, CircleHelp, CircleAlert, Link2, Target } from 'lucide-static';
/** Explicit assets; consumers may provide their own SVGs with the same contract. */
export interface IconAsset { readonly svg: string; readonly label: string; }
const asset = (svg: string, label: string): IconAsset => Object.freeze({svg, label});
export const defaultIcons = Object.freeze({
  library: asset(LibraryBig, 'Library'), selection: asset(SlidersHorizontal, 'Selection'), capture: asset(ScanLine, 'Capture'),
  model: asset(Network, 'Architecture model'), document: asset(FileText, 'Document'), decision: asset(GitBranch, 'Decision'),
  evidence: asset(ShieldCheck, 'Evidence'), question: asset(CircleHelp, 'Question'), pending: asset(CircleAlert, 'Pending'),
  reference: asset(Link2, 'Reference'), obligation: asset(Target, 'Obligation'),
});
export function iconDataURI(icon: IconAsset, color: string): string {
  return `data:image/svg+xml;base64,${Buffer.from(icon.svg.replaceAll('currentColor', color.replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;'))).toString('base64')}`;
}
