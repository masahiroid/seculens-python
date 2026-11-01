# SecuLens for Python

[English](README.md) | [日本語](README.jp.md)

SecuLensの独立したPython実装です。SPDX／CycloneDX JSONのSBOMをOSVの脆弱性情報と照合し、SPDXライセンス式のポリシー評価、PythonのAST解析、顧客提出用Word・JSONレポートの生成を行います。Python 3.11以降が必要です。Node.jsやTrivyの実行環境は不要です。

初期リリースであり、完全なSASTや法令遵守の判定ではありません。脆弱性の一致は指定したデータベースに基づく根拠、ASTの検出は確認候補です。

## インストール

[PyPI](https://pypi.org/project/seculens/)からインストールできます。

```sh
python -m pip install seculens
seculens
```

Wheelは[GitHub Releases](https://github.com/masahiroid/seculens-python/releases)からも取得できます。開発用の導入：

```sh
python -m venv .venv
# 仮想環境を有効にしてから実行
pip install -e '.[dev]'
seculens --version
```

## 対話ウィザード

引数なしで起動すると設定ウィザードが始まります。既定の言語は英語です。言語選択でEnterを押すと英語、`ja`を入力すると日本語になり、選択した言語をWordレポートにも使います。

```sh
seculens
# 日本語で直接開始
seculens wizard --lang ja
```

既存SBOMの検査またはSBOM生成を選び、パスとオプションを入力します。検査ではローカルOSVデータベースまたはOSVからの取得、任意のライセンスポリシーとソースフォルダー、顧客名・対象名・作成者、レポート形式、出力先、検出時の終了方針を設定します。ウィザードでは顧客提出用レポートが既定です。

最後に設定を確認して開始します。入力終了（EOF）や最後の確認で`n`を選ぶと中止し、Ctrl+Cでも中断できます。OSVへ送信する情報は実行前に表示します。相対パスは現在の作業フォルダーを基準に指定してください。従来の`scan`／`sbom`コマンドも使えます。

## オフラインでの実行例

リポジトリ内のサンプルを使う例：

```sh
seculens scan examples/cyclonedx.json --db examples/database.json \
  --policy examples/policy.json --source examples \
  --customer "サンプル顧客" --lang ja --output reports/sample
```

`examples/database.json`は実演用の架空データで、本番の脆弱性データベースではありません。`report.docx`、`report.json`、`sbom.json`、`database.json`を出力します。日本語WordレポートにはSIL Open Font LicenseのNoto Sans JPを埋め込みます。

OSVから候補を取得する場合は明示的に指定します。

```sh
seculens scan bom.json --fetch-osv --policy examples/policy.json --output reports/live
```

`api.osv.dev`へ送信するのはパッケージ名とエコシステムだけで、照合はローカルで行います。オフライン検査には`--db`を使います。ページ分割、撤回済み情報、バージョン範囲、脆弱性の別名、未対応のパッケージ識別情報、不完全な範囲を扱います。`no-match`は脆弱性がないことを保証しません。根拠ハッシュで検査に使ったSBOM・データベースのテキストを特定できます。

## SBOMの生成

[Syft](https://github.com/anchore/syft)を別途導入して実行します。

```sh
seculens sbom ./project --format cyclonedx --output bom.cdx.json
seculens sbom ./project --format spdx --output bom.spdx.json
```

`--syft /path/to/syft`で実行ファイルを指定できます。SecuLensは生成された出力を検証します。既存のCycloneDX 1.4〜1.7 JSON、SPDX 2.2／2.3 JSONも直接読み込めます。実装言語にかかわらず、Package URLでnpm、PyPI、Packagistの依存関係を識別します。SPDX 3とXMLは未対応です。

## ライセンスポリシー

```json
{"allow": ["MIT", "Apache-2.0", "BSD-3-Clause"], "deny": ["GPL-3.0-only"]}
```

SPDXの`AND`は全分岐の許可、`OR`はいずれかの選択肢の許可が必要です。`WITH`例外は完全に一致するポリシー項目が必要です。不明・未記載の式は要確認です。設定したポリシーの評価であり、すべての法的義務や規制への適合を判定するものではありません。

## Pythonソース解析

`--source`で`.py`ファイルを読み込み、インポート・実行せずに解析します。`eval`／`exec`、OSのシェル呼び出し、リテラルの`shell=True`を使う`subprocess`、pickleのデシリアライズ、安全なローダーが明示されていないYAML読み込みを確認候補として検出します。循環的複雑度が10を超える場合、ネスト深度が4を超える場合も確認対象です。

インポートと別名は構文から識別しますが、同名のローカル変数、動的な別名、データフロー、悪用可能性は解決しません。構文エラーは解析範囲の不足として記録します。仮想環境、依存関係・ビルドフォルダー、シンボリックリンクはスキップします。JS／TSソース解析には[TypeScript版](https://github.com/masahiroid/seculens)を使ってください。PHPソース解析には[独立したPHP版](https://github.com/masahiroid/seculens-php)を使ってください。

## スキーマ検証

```sh
seculens validate sbom.json                 # SPDX 2.2/2.3 または CycloneDX 1.4〜1.7 JSON
seculens validate report.json --kind report # SecuLens レポートスキーマ 1.1
```

同梱の公式スキーマ（`schemas/`、出典・ハッシュ・ライセンスはそのREADME参照）でオフライン検証します。出力はJSON `{valid, schema, errors[]}` です。終了コード `0` は妥当、`2` は不正・未対応バージョン・入力エラーです。構造と書式の検証のみで、SBOMの網羅性や検出結果の正しさは保証しません。

## 終了コードとAPI

- `0`：検査完了。検出結果が存在する場合もあります。
- `1`：`--fail-on-findings`指定時に脆弱性、拒否ライセンス、セキュリティ確認候補を検出。
- `2`：解析範囲の不足または実行エラー。指定時は終了コード1が優先されます。

```python
from seculens import scan_sbom, write_word_report

report = scan_sbom(sbom_text, records, policy={"allow": ["MIT"]}, customer="顧客名")
write_word_report(report, "report.docx", language="ja")
```

JSONスキーマ1.1はTypeScript版と共通です。照合にはPyPIのPEP 440、npmのSemVer、Composerのバージョン（安定度の順序 dev／alpha／beta／RC／stable／patch を含む）に対応します。ComposerのブランチやGitコミット範囲は未評価になる場合があります。顧客固有のリスク優先順位付け、到達可能性、コンテナー／OSのスキャン、完全なSASTは今後の課題です。レポートでは未実施の検査を実施済みと扱いません。

## 検証・開発

```sh
pytest
ruff check .
ruff format --check .
pip-audit
python -m build
python -m twine check dist/*
```

[セキュリティポリシー](SECURITY.md)も参照してください。コードはApache-2.0、同梱の日本語フォントはSIL OFLです。第三者の資産は[NOTICE](NOTICE)に記載しています。

## 顧客提出用レポート

`--report-style customer`で、表紙、要約、重大度の色分け、優先順の検出一覧、番号付き詳細、コンポーネントの評価範囲表、根拠ハッシュ、ページ番号を含むWordレポートを生成します。標準形式は`--report-style standard`で指定できます。コマンド直接実行では標準形式が既定です。

```sh
seculens scan bom.json --db database.json --policy policy.json \
  --customer "顧客企業" --target "顧客Webサービス" \
  --issuer "セキュリティ評価チーム" --lang ja \
  --report-style customer --output reports/customer
```

`--target`は対象システム名で、未指定時はSBOMのファイル名です。`--issuer`は表紙の作成者・文書の著者です。両方とも省略できます。レポートIDにはSBOMハッシュ、DBハッシュ、評価日時を使います。検出番号で一覧と詳細を対応させ、コード・ライセンスの確認状態と脆弱性の重大度を分けて表示します。

重大度の色はCritical／Highが赤、Mediumが黄、Lowが青、Noneが緑、Unratedが灰色です。色に加えてラベルも表示します。脆弱性の件数はコンポーネントごとに別名を統合し、カテゴリ別件数には確認候補も含めます。CVSSの0点／Noneは重大度の区分であり、脆弱性がないことの証明ではありません。

重大度は検証済みCVSS 3.0／3.1基本ベクトルまたは認識可能な`database_specific.severity`に基づきます。パッケージ固有のOSV `affected.severity`は、その影響エントリーの全体ベクトルより優先します。別名統合時には根拠を保存し、対応する重大度のうち最も高いものを表示します。情報源で評価が異なる場合もラベル・ベクトル・スコアをJSONに残します。CVSS 2／4や不正なベクトルは計算せず、他に使える情報がなければUnratedです。本文、AST確認候補、ライセンスから重大度を推測しません。

JSONスキーマ1.1には任意の`severity`（重大度、任意の基本スコア、情報源ID・フィールドパス・元の値）とCLIの`sourceAnalysis`実行情報を追加しています。表示用の並び替えで評価JSONは変更しません。Wordには重大度の根拠を簡潔に表示し、元のメタデータと参照先はJSONに保存します。このモードは表示形式と重大度の根拠を追加するもので、脆弱性の照合条件は変えません。

参照：[CVSS 3.1仕様](https://www.first.org/cvss/v3.1/specification-document)、[OSVスキーマ](https://ossf.github.io/osv-schema/)。

```python
write_word_report(report, "customer.docx", language="ja", style="customer", issuer="評価チーム")
```
