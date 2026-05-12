// Ambient declarations for side-effect asset imports.
//
// TypeScript 6 enables `noUncheckedSideEffectImports` by default, which
// rejects `import "fumadocs-ui/css/preset.css"` and similar unless a
// type declaration exists. These shims keep CSS imports type-safe across
// TS 5.x and TS 6.x.

declare module "*.css";
declare module "*.module.css" {
  const classes: { readonly [key: string]: string };
  export default classes;
}
