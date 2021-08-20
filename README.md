# Group Communication with OSCORE: RESTful Multiparty Access to a Data-Centric Web of Things (IEEE LCN 2021)

[![Paper][paper-badge]][paper-link]

This repository contains code and documentation to reproduce experimental results of the paper **[Group Communication with OSCORE: RESTful Multiparty Access to a Data-Centric Web of Things][paper-link]** published in the Proc. of 46th IEEE Conference on Local Computer Networks (LCN).

* Cenk Gündogan, Christian Amsüss, Thomas C. Schmidt, Matthias Wählisch,
**Group Communication with OSCORE: RESTful Multiparty Access to a Data-Centric Web of Things**,
In: Proc. of 46th IEEE Conference on Local Computer Networks, p. XX, Piscataway, NJ, USA: IEEE, 2021.

  **Abstract**
  > Content replication to many destinations is common in the IoT. IP multicast has proven inefficient due to a missing layer-2 support by IoT radios and its synchronous end-to-end transmission, which is susceptible to interference. Information-centric networking (ICN) introduced hop-wise multiparty dissemination of cacheable content, which proves valuable for lossy networks. Even Named-Data Networking (NDN), a prominent ICN, suffers from a lack of deployment. We explore a multiparty content distribution in an information-centric Web of Things built on CoAP. We augment CoAP proxies by request aggregation and response replication, which together with caches enable asynchronous group communication. Further, we integrate object security with OSCORE into the CoAP multicast proxy system for ubiquitous caching of certified content. We compare NDN, CoAP, and our data-centric approach in testbed experiments. Our findings indicate that multiparty content distribution with CoAP proxies performs equally well as NDN, while remaining compatible with the protocol world of CoAP.

Please follow our [Getting Started](getting-started.md) instructions for further information on how to compile and execute the code.

<!-- TODO: update URLs -->
[paper-link]:https://github.com/inetrg/IEEE-LCN-ICN-CoAP-21
<!-- [paper-badge]:https://img.shields.io/badge/Paper-IEEE%20Xplore-green -->
[paper-badge]:https://img.shields.io/badge/Paper-IEEE%20Xplore-gray
