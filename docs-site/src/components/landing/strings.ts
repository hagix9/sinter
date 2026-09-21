export interface LandingStrings {
  heroTitle: string;
  heroSub: string;
  heroPrimaryCta: string;
  heroSecondaryCta: string;
  heroFacts: string;
  demoTitle: string;
  demoNote: string;
  terminalTitle: string;
  capabilitiesTitle: string;
  capPlanSub: string;
  capPlanDesc: string;
  capApplySub: string;
  capApplyDesc: string;
  capAuditSub: string;
  capAuditDesc: string;
  recipeTitle: string;
  recipeNote: string;
  recipeCta: string;
  flowTitle: string;
  flowNote: string;
  flowRecipeSub: string;
  flowDeclare: string;
  flowSinterSub: string;
  flowObserve: string;
  flowConverge: string;
  flowTargetSub: string;
  flowPlanSub: string;
  flowApplySub: string;
  flowAuditSub: string;
  trustTitle: string;
  trustPoints: string[];
  trustCta: string;
  aiTitle: string;
  aiIntro: string;
  webmcpTitle: string;
  webmcpNote: string;
  webmcpAskLabel: string;
  webmcpQuestion: string;
  webmcpToolLabel: string;
  webmcpTool: string;
  webmcpAnswerLabel: string;
  webmcpAnswer: string;
  webmcpDocsCta: string;
  coremcpTitle: string;
  coremcpNote: string;
  coremcpPoints: string[];
  coremcpBoundary: string;
  platformsTitle: string;
  platformsLine: string;
  platformsStatus: string;
  platformsNote: string;
  platformsCta: string;
  installTitle: string;
  installNote: string;
  installCta: string;
  docsTitle: string;
  docsNote: string;
  docsCta: string;
  quickstartCta: string;
  githubCta: string;
}

export const strings: Record<'en' | 'ja', LandingStrings> = {
  en: {
    heroTitle: 'Configuration you can see before it changes anything.',
    heroSub:
      'Sinter is a single Rust binary that plans, applies, and audits Linux configuration over SSH.',
    heroPrimaryCta: 'Get started',
    heroSecondaryCta: 'See it run',
    heroFacts: 'One binary · Zero agents · Plan / Apply / Audit · SSH',
    demoTitle: 'See it run',
    demoNote:
      'Real output from an Ubuntu 24.04 host — validate, plan, apply, audit.',
    terminalTitle: 'sinter — web01',
    capabilitiesTitle: 'Three commands. One loop.',
    capPlanSub: 'read-only',
    capPlanDesc:
      'Observes the target and reports exactly what would change — nothing is modified.',
    capApplySub: 'explicit mutation',
    capApplyDesc:
      'Converges the target toward the declared state, fails fast on the first error.',
    capAuditSub: 'read-only',
    capAuditDesc:
      'Compares actual state with the recipe and reports compliance or drift.',
    recipeTitle: 'A recipe is just YAML',
    recipeNote:
      'Declare the state. Sinter handles observation and convergence — no agent or runtime on the managed host.',
    recipeCta: 'Recipe format reference',
    flowTitle: 'How Sinter works',
    flowNote:
      'Sinter loads the recipe, observes the target over SSH, and reports or converges. Nothing runs on the target permanently.',
    flowRecipeSub: 'desired state · YAML',
    flowDeclare: 'load',
    flowSinterSub: 'single binary · runs on your machine',
    flowObserve: 'observe',
    flowConverge: 'converge (apply only)',
    flowTargetSub: 'no agent · no daemon',
    flowPlanSub: 'read-only preview',
    flowApplySub: 'explicit mutation',
    flowAuditSub: 'PASS / DRIFT report',
    trustTitle: 'Built to fail closed',
    trustPoints: [
      'Strict SSH host-key verification — unknown or mismatched keys refuse, never prompt.',
      'Unsafe paths and unexpected symlinks stop execution instead of guessing.',
      'Files are published atomically — no half-written configuration.',
      'Failures and indeterminate states are reported honestly, never hidden.',
    ],
    trustCta: 'Execution model',
    aiTitle: 'AI integration',
    aiIntro:
      'Two separate surfaces: one lets AI read this documentation, the other lets AI use bounded Sinter capabilities.',
    webmcpTitle: 'Website WebMCP',
    webmcpNote:
      'AI → Sinter documentation. Browser-side Site Tools let an agent look up Sinter docs — read-only, documentation only.',
    webmcpAskLabel: 'You ask your AI',
    webmcpQuestion: 'Does Sinter support Rocky Linux 10?',
    webmcpToolLabel: 'The AI consults the docs via',
    webmcpTool: 'sinter_get_compatibility',
    webmcpAnswerLabel: 'Answered from Sinter\u2019s documentation',
    webmcpAnswer:
      'Yes. Rocky Linux 10 on x86_64 is supported and acceptance-tested, using the dnf backend.',
    webmcpDocsCta: 'How Website WebMCP works',
    coremcpTitle: 'Core MCP',
    coremcpNote:
      'AI → bounded Sinter capabilities, without arbitrary SSH authority.',
    coremcpPoints: [
      'Validate and inspect recipes',
      'Plan changes against supplied facts',
      'List administrator-named targets',
      'Run read-only plan and audit on those targets',
    ],
    coremcpBoundary:
      'Named targets only · read-only Plan/Audit · no Apply · no arbitrary SSH or commands',
    platformsTitle: 'Supported platforms',
    platformsLine:
      'Ubuntu 24.04 & 26.04 · Rocky Linux 9 & 10 · RHEL 9 & 10 · AlmaLinux 9 & 10',
    platformsStatus: 'amd64/x86_64 — supported, acceptance-tested',
    platformsNote:
      'Oracle Linux (x86_64, dnf) is expected compatible but not acceptance-tested.',
    platformsCta: 'Full compatibility matrix',
    installTitle: 'Install',
    installNote:
      'Linux x86_64. The installer verifies checksums and version before placing the binary.',
    installCta: 'Installation guide',
    docsTitle: 'Documentation',
    docsNote: 'Guides, concepts, recipe format, and the full resource reference.',
    docsCta: 'Read the docs',
    quickstartCta: 'Quick start',
    githubCta: 'GitHub',
  },
  ja: {
    heroTitle: '変更する前に、何が変わるかを見える構成管理。',
    heroSub:
      'Sinter は SSH 経由で Linux の構成を plan・apply・audit する単一の Rust バイナリです。',
    heroPrimaryCta: 'はじめる',
    heroSecondaryCta: '動作を見る',
    heroFacts: '1 バイナリ · エージェント不要 · Plan / Apply / Audit · SSH',
    demoTitle: '動作を見る',
    demoNote:
      'Ubuntu 24.04 ホストでの実際の出力 — validate、plan、apply、audit。',
    terminalTitle: 'sinter — web01',
    capabilitiesTitle: '3 つのコマンド、1 つのループ。',
    capPlanSub: '読み取り専用',
    capPlanDesc:
      'ターゲットを観測し、何が変わるかを正確に報告します — 何も変更しません。',
    capApplySub: '明示的な変更',
    capApplyDesc:
      '宣言された状態へターゲットを収束させ、最初のエラーで fail-fast します。',
    capAuditSub: '読み取り専用',
    capAuditDesc:
      '実際の状態とレシピを比較し、準拠またはドリフトを報告します。',
    recipeTitle: 'レシピは YAML だけ',
    recipeNote:
      '状態を宣言するだけ。観測と収束は Sinter が処理します — 管理対象ホストにエージェントもランタイムも不要。',
    recipeCta: 'レシピ形式リファレンス',
    flowTitle: 'Sinter の仕組み',
    flowNote:
      'Sinter はレシピを読み込み、SSH 経由でターゲットを観測し、報告または収束します。ターゲットに常駐するものはありません。',
    flowRecipeSub: '望ましい状態 · YAML',
    flowDeclare: '読み込み',
    flowSinterSub: '単一バイナリ · 手元のマシンで動作',
    flowObserve: '観測',
    flowConverge: '収束 (apply のみ)',
    flowTargetSub: 'エージェント不要 · デーモンなし',
    flowPlanSub: '読み取り専用プレビュー',
    flowApplySub: '明示的な変更',
    flowAuditSub: 'PASS / DRIFT レポート',
    trustTitle: 'フェイルクローズ設計',
    trustPoints: [
      '厳格な SSH ホスト鍵検証 — 未知・不一致の鍵は拒否し、確認プロンプトに頼りません。',
      '不安全なパスや予期しないシンボリックリンクは推測せず実行を停止します。',
      'ファイルは原子的に公開 — 中途半端な状態の設定を残しません。',
      '失敗と不確定状態は隠さず正直に報告します。',
    ],
    trustCta: '実行モデル',
    aiTitle: 'AI 連携',
    aiIntro:
      '2 つの独立した仕組み: ひとつは AI がこのドキュメントを読むため、もうひとつは AI が制限された Sinter 機能を使うため。',
    webmcpTitle: 'Website WebMCP',
    webmcpNote:
      'AI → Sinter ドキュメント。ブラウザ側 Site Tools がエージェントに Sinter ドキュメントの参照を提供します — 読み取り専用、ドキュメントのみ。',
    webmcpAskLabel: 'AI に質問する',
    webmcpQuestion: 'Sinter は Rocky Linux 10 をサポートしていますか?',
    webmcpToolLabel: 'AI はドキュメントを参照する',
    webmcpTool: 'sinter_get_compatibility',
    webmcpAnswerLabel: 'Sinter のドキュメントから回答',
    webmcpAnswer:
      'はい。x86_64 の Rocky Linux 10 は dnf バックエンドでサポートされ、受け入れテスト済みです。',
    webmcpDocsCta: 'Website WebMCP の仕組み',
    coremcpTitle: 'Core MCP',
    coremcpNote:
      'AI → 制限された Sinter 機能。任意の SSH 権限は渡しません。',
    coremcpPoints: [
      'レシピの検証と検査',
      '提供されたファクトに対する計画',
      '管理者が定義した名前付きターゲットの列挙',
      'それらのターゲットへの読み取り専用 plan/audit',
    ],
    coremcpBoundary:
      '名前付きターゲットのみ · 読み取り専用 Plan/Audit · Apply なし · 任意の SSH・コマンド実行なし',
    platformsTitle: '対応プラットフォーム',
    platformsLine:
      'Ubuntu 24.04 & 26.04 · Rocky Linux 9 & 10 · RHEL 9 & 10 · AlmaLinux 9 & 10',
    platformsStatus: 'amd64/x86_64 — サポート対象・受け入れテスト済み',
    platformsNote:
      'Oracle Linux (x86_64, dnf) は互換見込みですが受け入れテストは未実施です。',
    platformsCta: '互換性マトリックス全文',
    installTitle: 'インストール',
    installNote:
      'Linux x86_64。インストーラはバイナリ配置前にチェックサムとバージョンを検証します。',
    installCta: 'インストールガイド',
    docsTitle: 'ドキュメント',
    docsNote: 'ガイド、概念、レシピ形式、完全なリソースリファレンス。',
    docsCta: 'ドキュメントを読む',
    quickstartCta: 'クイックスタート',
    githubCta: 'GitHub',
  },
};
