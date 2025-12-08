#include "runners/TonlibWrapper.h"
#include "td/actor/actor.h"
#include "td/utils/port/signals.h"
#include "td/utils/OptionParser.h"
#include "td/utils/Time.h"
#include <iostream>

using namespace cocoon;
namespace tonlib_api = ton::tonlib_api;

struct Options {
  std::string ton_config_filename;
  bool is_testnet = true;
};

td::actor::Task<TonlibWrapper::SyncInfo> do_sync(Options opts) {
  TonlibWrapper tonlib_client;
  co_await tonlib_client.initialize(opts.ton_config_filename, opts.is_testnet);
  auto sync_info = co_await tonlib_client.sync();
  LOG(INFO) << "Synced up to " << sync_info;
  co_return sync_info;
}

td::actor::Task<td::Unit> sync(Options opts) {
  LOG(INFO) << "Started: config=" << opts.ton_config_filename << " net=" << (opts.is_testnet ? "testnet" : "mainnet");
  auto sync_info = (co_await do_sync(opts).wrap()).move_as_ok();
  LOG(INFO) << "Finished";
  // Print blockchain timestamp from sync_info to avoid race condition
  std::cout << sync_info.last_synced_ts << std::endl;
  std::_Exit(0);
}

int main(int argc, char* argv[]) {
  SET_VERBOSITY_LEVEL(verbosity_INFO);
  td::set_default_failure_signal_handler().ensure();

  td::OptionParser options;
  std::string ton_config = "../reprodebian/test-spec/spec-proxy/runtime/global.config.json";
  bool use_testnet = false;

  options.set_description("SimpleSyncRunner - TON sync test");
  options.add_checked_option('c', "ton-config", "TON config file", [&](td::Slice arg) {
    ton_config = arg.str();
    return td::Status::OK();
  });
  options.add_checked_option('t', "testnet", "Use testnet", [&](td::Slice arg) {
    use_testnet = true;
    return td::Status::OK();
  });
  options.add_checked_option('h', "help", "Show help", [&](td::Slice arg) {
    LOG(ERROR) << options;
    std::exit(0);
    return td::Status::OK();
  });

  auto S = options.run(argc, argv);
  if (S.is_error()) {
    LOG(ERROR) << "Parse error: " << S.error();
    LOG(ERROR) << options;
    return 1;
  }

  td::set_signal_handler(td::SignalType::User, [](int) { td::actor::SchedulerContext::get()->stop(); }).ensure();

  td::actor::Scheduler scheduler({2});

  scheduler.run_in_context([&] {
    Options opts{.ton_config_filename = ton_config, .is_testnet = use_testnet};
    sync(opts).start().detach();
  });

  scheduler.run();
  return 0;
}
