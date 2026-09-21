// SocEyes — custom SVG icon set.
// 24x24 stroke icons matched to the tech-brutalist design system:
// 2px strokes, square caps, no fills. Zero third-party icon code —
// every glyph is drawn to match this product.

import type { SVGProps } from "react";

type IconProps = SVGProps<SVGSVGElement> & { size?: number };

function Icon({ size = 18, children, ...rest }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="square"
      strokeLinejoin="miter"
      aria-hidden="true"
      {...rest}
    >
      {children}
    </svg>
  );
}

/* Radar dish — Mission */
export function IconRadar(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx={12} cy={12} r={9} />
      <circle cx={12} cy={12} r={4.5} />
      <path d="M12 12 18.5 5.5" />
      <circle cx={12} cy={12} r={1} fill="currentColor" stroke="none" />
    </Icon>
  );
}

/* Grid of command panels — Command Center */
export function IconLayout(props: IconProps) {
  return (
    <Icon {...props}>
      <rect x={3} y={3} width={8} height={8} />
      <rect x={13} y={3} width={8} height={5} />
      <rect x={13} y={10} width={8} height={11} />
      <rect x={3} y={13} width={8} height={8} />
    </Icon>
  );
}

/* Stacked log lines — Logs */
export function IconScroll(props: IconProps) {
  return (
    <Icon {...props}>
      <rect x={4} y={3} width={16} height={18} />
      <path d="M8 8h8M8 12h8M8 16h5" />
    </Icon>
  );
}

/* Notification bell — Alerts */
export function IconBell(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M6 10a6 6 0 0 1 12 0c0 4 1.5 5.5 2.5 6.5H3.5C4.5 15.5 6 14 6 10Z" />
      <path d="M10 19.5a2.2 2.2 0 0 0 4 0" />
    </Icon>
  );
}

/* Cracked shield — Incidents */
export function IconShieldAlert(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 2 4.5 5v6c0 5 3 8.5 7.5 11 4.5-2.5 7.5-6 7.5-11V5L12 2Z" />
      <path d="M12 8v4M12 15.5v.5" />
    </Icon>
  );
}

/* Clipboard with check — Audit */
export function IconClipboardCheck(props: IconProps) {
  return (
    <Icon {...props}>
      <rect x={5} y={4} width={14} height={17} />
      <path d="M9 4.5V3h6v1.5" />
      <path d="M9 12.5l2.5 2.5L16 10.5" />
    </Icon>
  );
}

/* Open box — Packs */
export function IconPackage(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M3 8l9-5 9 5v8l-9 5-9-5V8Z" />
      <path d="M3 8l9 5 9-5M12 13v8" />
    </Icon>
  );
}

/* Storefront — Marketplace */
export function IconStore(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M4 9l1.5-5h13L20 9" />
      <path d="M4 9h16v11H4V9Z" />
      <path d="M9 20v-6h6v6" />
    </Icon>
  );
}

/* Clock with arrow — Runs */
export function IconHistory(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M3.5 12a8.5 8.5 0 1 0 2.5-6" />
      <path d="M3.5 3v4h4" />
      <path d="M12 7.5V12l3 2" />
    </Icon>
  );
}

/* Play in frame — Playbooks */
export function IconPlaySquare(props: IconProps) {
  return (
    <Icon {...props}>
      <rect x={3} y={3} width={18} height={18} />
      <path d="M10 8.5v7l6-3.5-6-3.5Z" />
    </Icon>
  );
}

/* Shield with check — Responses */
export function IconShieldCheck(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 2 4.5 5v6c0 5 3 8.5 7.5 11 4.5-2.5 7.5-6 7.5-11V5L12 2Z" />
      <path d="M8.5 12l2.5 2.5 4.5-4.5" />
    </Icon>
  );
}

/* Circuit-node bot — Agents */
export function IconBot(props: IconProps) {
  return (
    <Icon {...props}>
      <rect x={4} y={8} width={16} height={12} />
      <path d="M12 8V4M9.5 4h5" />
      <circle cx={9} cy={14} r={1} fill="currentColor" stroke="none" />
      <circle cx={15} cy={14} r={1} fill="currentColor" stroke="none" />
      <path d="M4 13H2M22 13h-2" />
    </Icon>
  );
}

/* Shield — generic defense */
export function IconShield(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 2 4.5 5v6c0 5 3 8.5 7.5 11 4.5-2.5 7.5-6 7.5-11V5L12 2Z" />
    </Icon>
  );
}

/* Workflow nodes — pipeline */
export function IconWorkflow(props: IconProps) {
  return (
    <Icon {...props}>
      <rect x={3} y={3} width={7} height={7} />
      <rect x={14} y={14} width={7} height={7} />
      <path d="M10 6.5h5.5a2 2 0 0 1 2 2V14" />
    </Icon>
  );
}

/* Siren — critical containment */
export function IconSiren(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M6 17v-4a6 6 0 0 1 12 0v4" />
      <rect x={3.5} y={17} width={17} height={4} />
      <path d="M12 3v2M4 7l1.5 1.5M20 7l-1.5 1.5" />
    </Icon>
  );
}
