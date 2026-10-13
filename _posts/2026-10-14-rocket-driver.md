---
title: "Rocket Driver (1)"
date: 2026-10-14 19:00:00 +0900
categories: [Linux Kernel, Rocket]
tags: [linux-kernel, rocket, npu, rockchip, rk3588]
published: false
---

## Introduction

Rocket은 Rockchip RK3588의 NPU를 지원하는 Linux NPU 드라이버이다. 이 드라이버는 비교적 최근에 메인라인에 병합 되었는데, 원래 Rockchip 모델의 NPU는 vendor kernel에서만 사용할 수 있었고 이로 인해 여러 제약들이 많았다고 한다. 그래서 Tomeu Vizoso라는 사람이 reverse engineering을 통해 처음부터 새로 작성해 rocket을 개발하였으며 메인라인에 병합되었다. rocket은 유저 공간 드라이버로 mesa를 사용한다. 커널 드라이버는 전원 관리, 버퍼 할당, job 제출 정도만 하고 나머지는 전부 mesa 쪽에서 처리한다고 한다.

나는 최근 리눅스 커널 기여를 위해 드라이버를 찾고 있었고 rocket은 병합된지 얼마 안되었기에 상대적으로 기여할 거리가 많다고 생각하여 선택했다. 이 글은 rocket의 소스 코드를 분석하며 정리한 글이다.

## Hardware Overview

먼저, Rocket이 지원하는 RK3588은 ARM64 아키텍처 기반의 SoC 칩이며, Device Tree를 통해 하드웨어 정보를 기술한다. NPU 노드는 `rk3588-base.dtsi`에 정의되어 있다.

