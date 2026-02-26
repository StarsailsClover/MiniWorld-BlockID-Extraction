# MiniWorld-BlockID-Extraction
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)  

一个用于提取《迷你世界（MiniWorld）》Block ID（方块ID）的工具项目，旨在为跨平台开发、模组制作、数据解析等场景提供精准的方块ID数据支撑。

## 🌟 项目简介
MiniWorld-BlockID-Extraction 专注于从迷你世界的资源文件/安装包中自动化提取方块ID信息，并将其整理为结构化格式（如JSON/CSV），方便开发者、研究者快速获取和使用方块ID数据，降低数据采集成本。

本项目仅用于**学习和技术研究**，请勿用于商业用途或违反游戏用户协议的场景。

## 📋 核心功能
- 🚀 自动化提取迷你世界各版本的方块ID及关联元数据（名称、类型、属性等）
- 📊 输出多格式结构化数据（JSON/CSV/TXT），便于后续分析和集成
- 🔍 支持指定版本资源文件解析，适配不同版本的方块ID变更
- 🛠️ 轻量无冗余，核心逻辑简洁易懂，易于二次开发和定制
- 💻 跨平台兼容（Windows/Linux/macOS）

## 🛠️ 环境要求
- Python 3.8+
- 依赖库（按需安装）：
  ```
  pandas>=1.5.0
  json5>=0.9.10
  click>=8.1.0
  ```

## 🚀 使用方法
### 1. 克隆仓库
```bash
git clone https://github.com/StarsailsClover/MiniWorld-BlockID-Extraction.git
cd MiniWorld-BlockID-Extraction
```

### 2. 安装依赖
```bash
pip install -r requirements.txt
```

### 3. 准备资源文件
将迷你世界的资源包/安装包中包含方块配置的文件（如`block_config.json`、`blocks.dat`等）放入`./input`目录下（若无该目录请手动创建）。

### 4. 运行提取脚本
```bash
# 基础使用（默认输出JSON格式到output目录）
python extract_blockid.py

# 自定义输出格式（如CSV）
python extract_blockid.py --format csv

# 指定输入文件路径
python extract_blockid.py --input ./custom_input/block_config.json

# 指定输出路径
python extract_blockid.py --output ./my_output/block_ids.csv
```

### 5. 查看结果
提取完成后，结果文件会生成在`./output`目录下，可直接打开查看或导入其他项目使用。

## 📂 项目结构
```
MiniWorld-BlockID-Extraction/
├── input/               # 资源文件输入目录（需手动创建/放入文件）
├── output/              # 提取结果输出目录（自动生成）
├── extract_blockid.py   # 核心提取脚本
├── requirements.txt     # 依赖清单
├── LICENSE              # 许可证文件
└── README.md            # 项目说明文档
```

## ❓ 常见问题
### Q1: 提取失败/无数据输出？
A1: 请检查：
- 输入文件是否为对应版本的有效方块配置文件；
- Python版本是否满足3.8+；
- 依赖库是否完整安装；
- 输入文件路径是否正确。

### Q2: 支持哪些版本的迷你世界？
A2: 目前主流正式版均适配，若遇到特定版本不兼容，可提交Issue反馈。

### Q3: 能否提取除Block ID外的其他数据？
A3: 项目核心为Block ID提取，如需扩展（如物品ID、实体ID），可基于核心逻辑二次开发，或提交Feature Request。

## 🤝 贡献指南
欢迎各位开发者参与贡献：
1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交修改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开 Pull Request

同时，也欢迎提交Issue反馈bug、提出新功能建议。

## 📄 许可证
本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件。

## ⚠️ 免责声明
1. 本项目仅用于学习和技术研究，不代表与《迷你世界》官方有任何关联；
2. 使用本项目需遵守相关法律法规及《迷你世界》用户协议，禁止用于商业、侵权等非法场景；
3. 开发者不对因使用本项目导致的任何问题承担责任。
