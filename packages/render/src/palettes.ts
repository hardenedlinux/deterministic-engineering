// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

/** Open semantic color slots. CSS owns the color syntax. */
export interface Palette {
  readonly background:string;readonly surface:string;readonly ink:string;readonly muted:string;readonly border:string;
  readonly accent:string;readonly secondary:string;readonly tint:string;readonly secondaryTint:string;readonly onAccent:string;
  readonly supported:string;readonly pending:string;readonly conflict:string;readonly[name:string]:string;
}
export const palettes:Readonly<Record<string,Palette>>=Object.freeze({
  blueprint:Object.freeze({background:'#F0F5F7',surface:'#FFFFFF',ink:'#193348',muted:'#627787',border:'#D5E1E7',accent:'#246E86',secondary:'#686084',tint:'#E7F1F5',secondaryTint:'#F0EDF5',onAccent:'#FFFFFF',supported:'#237C69',pending:'#9A6C25',conflict:'#A84C60'}),
  graphite:Object.freeze({background:'#131E28',surface:'#1C2935',ink:'#E5EEF5',muted:'#A3B6C5',border:'#354956',accent:'#8BCADD',secondary:'#BFB4DD',tint:'#263D4B',secondaryTint:'#343449',onAccent:'#16222C',supported:'#8BCEAE',pending:'#E0BE81',conflict:'#ECA3AC'}),
  'field-notes':Object.freeze({background:'#F4F0E7',surface:'#FFFEF9',ink:'#39382F',muted:'#797365',border:'#E0D8C5',accent:'#8D6738',secondary:'#546D5B',tint:'#F4EAD7',secondaryTint:'#EAF0E5',onAccent:'#FFFFFF',supported:'#3B785A',pending:'#A67127',conflict:'#A04F4B'}),
  ocean:Object.freeze({background:'#F6FAF9',surface:'#FFFFFF',ink:'#163C43',muted:'#496A70',border:'#C9DDDA',accent:'#087E82',secondary:'#946044',tint:'#E1F1EC',secondaryTint:'#F4EADA',onAccent:'#FFFFFF',supported:'#237653',pending:'#986320',conflict:'#A13E54'}),
  ember:Object.freeze({background:'#FCF8F3',surface:'#FFFEFB',ink:'#332E2C',muted:'#72635D',border:'#E3D6CA',accent:'#A4492C',secondary:'#526B75',tint:'#F7E9DD',secondaryTint:'#E8EFF0',onAccent:'#FFFFFF',supported:'#356D56',pending:'#8D661A',conflict:'#A03D50'}),
});
