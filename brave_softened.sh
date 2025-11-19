#!/usr/bin/env bash
export TZ=America/New_York
P1="6.6.6.6:6666"
P2="7.7.7.7:7777"
export http_proxy="http://$P1"
export https_proxy="$http_proxy"
export ALL_PROXY="$http_proxy"
export NO_PROXY=""

exec brave \
  --force-dark-mode --password-store=gnome-libsecret --no-first-run \
  --proxy-server="http://$P1;http://$P2" \
  --proxy-bypass-list="<local>,localhost,127.0.0.1" \
  --disable-webrtc \
  --window-size=1920,1080 --site-per-process \
  \
  --enable-features=\
MojoIpcz,\
StrictMojoCore,\
IsolateOrigins,\
SitePerProcess,\
NetworkServiceSandbox,\
AudioServiceSandbox,\
StrictSiteIsolation,\
V8ForceMemoryCage,\
MiraclePtr,\
CrossOriginOpenerPolicyByDefault,\
AudioServiceOutOfProcess,\
PartitionAllocBackupRefPtr,\
PartitionConnectionsByNetworkIsolationKey,\
PartitionHttpServerPropertiesByNetworkIsolationKey,\
BlockInsecurePrivateNetworkRequests,\
ThirdPartyStoragePartitioning,\
PartitionAllocGigaCage,\
BackupRefPtrNoEntryDeletion,\
PartitionAllocSchedulerLoopQuarantine,\
PartitionAllocZappingByFreeFlags,\
PartitionVisitedLinks,\
PartitionedCookies,\
SplitCacheByNetworkIsolationKey,\
PartitionDiskCache,\
PartitionIndexedDB,\
PartitionBlobCache,\
PartitionCodeCache,\
PartitionedBlobUrlStore,\
StrictOriginIsolation,\
IsolateSandboxedIframes,\
OriginAgentClusterDefaultEnabled,\
StrictExtensionIsolation,\
SameSiteByDefaultCookies,\
CookiesWithoutSameSiteMustBeSecure,\
PartitionSSLSessionsByNetworkIsolationKey,\
PartitionNelAndReportingByNetworkIsolationKey,\
SplitHostCacheByNetworkIsolationKey,\
BlockInsecureDownloads,\
MixedContentAutoupgrade,\
SameSiteDefaultChecksMethodRigorously,\
RawPtrZeroOnConstruct,\
RawPtrZeroOnMove,\
RawPtrZeroOnDestruct,\
PartitionAllocPCScan,\
PartitionAllocMemoryReclaimer,\
PartitionAllocLazyCommit,\
UsePartitionAllocForArrayBufferAllocator,\
PartitionAllocUseFreelist,\
PartitionAllocUseAltBuckets,\
V8UntrustedCodeMitigations,\
V8VirtualAddressSpaceReservation,\
EnforceNoopenerOnPopups,\
IsolateExtensions,\
IsolatedAppOrigins,\
WasmCodeProtection,\
WasmTrapHandler \
  \
  --disable-features=\
AutofillServerCommunication,\
MediaRouter,\
DialMediaRouteProvider,\
CastMediaRouteProvider,\
PrivacySandboxAdsAPIsOverride,\
AttributionReporting,\
Topics,\
PrivateAggregationAPI,\
Fledge,\
FencedFrames,\
SharedStorageAPI,\
BackForwardCache,\
Prerender2,\
OptimizationGuideHintDownloading \
  \
  --disable-background-networking \
  --disable-sync \
  --disable-default-apps \
  --disable-component-update \
  --no-referrers \
  --deny-permission-prompts \
  --enable-strict-mixed-content-checking \
  --disable-notifications \
  "$@"
