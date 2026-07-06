export interface Device {
  public_key: string;
  name: string;
  endpoint: string | null;
  tunnel_ip: string;
  tags: string[];
  candidates: string[];
}

export interface PolicyRule {
  src: string[];
  dst: string[];
}

export interface Policy {
  allow_all: boolean;
  rules: PolicyRule[];
}
