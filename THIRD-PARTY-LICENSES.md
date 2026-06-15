# Third-Party Licenses

This project distributes or downloads the following third-party software as
part of its deployment. Each dependency, its version, source, and license are
listed below, followed by the verbatim license text where redistribution
applies.

The binaries are not committed to this repository. They are assembled into a
shared AWS Lambda Layer at `cdk synth` time by
`packages/infra/lib/binary-stack.ts`:

- **skopeo** is built from source inside a digest-pinned `golang:1.25-alpine`
  container and the resulting binary is bundled into the layer (redistributed).
- **inspector-sbomgen** is downloaded from the official AWS S3 URL with SHA256
  verification at synth time and is **not** redistributed by this project.

| Dependency           | Version  | Source                                            | License                          |
| -------------------- | -------- | ------------------------------------------------- | -------------------------------- |
| skopeo               | v1.23.0  | https://github.com/containers/skopeo              | Apache License 2.0               |
| inspector-sbomgen    | 1.14.1   | https://docs.aws.amazon.com/inspector/latest/user/sbomgen.html | AWS Intellectual Property License |

---

## skopeo

- **Version:** v1.23.0
- **Source:** https://github.com/containers/skopeo
- **License:** Apache License 2.0

skopeo is built from source and the compiled binary is redistributed in this
project's Lambda Layer. In accordance with Section 4 of the Apache License 2.0,
the full license text is reproduced below. The upstream project ships no
`NOTICE` file at the `v1.23.0` tag.

```
                                 Apache License
                           Version 2.0, January 2004
                        https://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```

---

## inspector-sbomgen (Amazon Inspector SBOM Generator)

- **Version:** 1.14.1
- **Source:** https://docs.aws.amazon.com/inspector/latest/user/sbomgen.html
- **Download:** https://amazon-inspector-sbomgen.s3.amazonaws.com/1.14.1/linux/amd64/inspector-sbomgen.zip
- **License:** AWS Intellectual Property License

inspector-sbomgen is downloaded from the official AWS distribution point at
synth time (with SHA256 verification) and executed inside the scanner Lambda. It
is **not** redistributed by this project. The tool is governed by the AWS
Intellectual Property License, whose Section 4 restricts redistribution and
creation of derivative works — which is why this project fetches the official
binary rather than vendoring it.

The license text that ships inside the official archive
(`LICENSE.txt`) is reproduced below for reference. The archive also bundles a
`licenses/` directory enumerating the licenses of inspector-sbomgen's own
third-party components (Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause); consult
the downloaded archive for those verbatim texts.

```
AWS Intellectual Property License
Last Updated: September 17, 2021

This Intellectual Property License ("License") governs your use of AWS Content
and the Services. Capitalized terms used but not defined in this License are
defined in the AWS Customer Agreement or other agreement with us governing your
use of the Services (the "Agreement").

1. AWS Licensor
If the geographic location associated with your AWS account is any country
within Europe, the Middle East, or Africa ("EMEA"), then Amazon Web Services
EMEA SARL ("AWS Europe") grants this License. If the geographic location
associated with your AWS account is any country outside of EMEA, then Amazon Web
Services, Inc. ("AWS, Inc.") grants this License. "AWS Europe" and "AWS, Inc."
are individually referred to herein as an "AWS Licensor".

2. No Agency
This License forms a separate agreement between you and the AWS Licensor without
any further action required by the parties. AWS Licensor grants this License in
its own capacity and no other party is acting as agent of AWS Licensor or has
capacity to bind AWS Licensor.

3. License
AWS Licensor or its licensors own all right, title, and interest in and to the
Services, AWS Content, and all related technology and intellectual property
rights. Subject to the terms of this License and the Agreement, AWS Licensor
grants you a limited, royalty-free, revocable, non-exclusive, non-sublicensable,
non-transferrable license to copy and use the AWS Content solely in connection
with your permitted use of the Services during the Term. Solely to the extent
that applicable law requires the exercise of intellectual property rights owned
by AWS Licensor or its licensors for you to access or use any Service, AWS
Licensor grants you a limited, royalty-free, revocable, non-exclusive,
non-sublicensable and non-transferrable license to exercise such intellectual
property rights during the Term and subject to the terms of this License and the
Agreement. No other entity is entitled to or purports to grant or procure the
grant of this License. Except as expressly provided in this Section 3, you
obtain no other rights under the Agreement or this License from AWS Licensor,
its affiliates or suppliers to the Services and AWS Content, including any
related intellectual property rights. Some AWS Content and Third-Party Content
may be provided to you under a separate license, such as the Apache License,
Version 2.0, or other open source license. In the event of a conflict between
this License and any separate license, the separate license will prevail with
respect to the AWS Content or Third-Party Content that is the subject of such
separate license.

4. License Restrictions
Neither you nor any End User will use the Services or AWS Content in any manner
or for any purpose other than as expressly permitted by this License and the
Agreement. Neither you nor any End User will, or will attempt to (a) modify,
distribute, alter, tamper with, repair, or otherwise create derivative works of
any Content included in the Services or AWS Content (except to the extent such
Content is provided to you under a separate license that expressly permits the
creation of derivative works), or (b) sublicense the Services or AWS Content.
These license restrictions will continue to apply following the termination of
this License.
```
