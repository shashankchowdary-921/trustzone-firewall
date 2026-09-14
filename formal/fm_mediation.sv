// fm_mediation.sv — HARDENED COMPLETE-MEDIATION PROOF WRAPPER (O1)
// v2: independent inline reference decision (no shared code with DUT),
//     write-FSM shadow FSM, RID-integrity shadow, fault-log delta invariant,
//     irq-equation, timestamp-progress check. Config anyconst => ALL configs.rreee
`default_nettype none
module fm_mediation (
  input wire clk
);
  localparam int NR = 16, AW = 32, DW = 32, IW = 4;
  localparam int DEPTH = 4;

  // ---- symbolic configuration ----
  (* anyconst *) reg [NR-1:0]        cfg_enable;
  (* anyconst *) reg [NR*AW-1:0]     cfg_base;
  (* anyconst *) reg [NR*AW-1:0]     cfg_mask;
  (* anyconst *) reg [NR*6-1:0]      cfg_perm;
  (* anyseq *)   reg                 int_en;

  // ---- free stimulus ----
  (* anyseq *) reg              s_arvalid;
  (* anyseq *) reg [IW-1:0]     s_arid;
  (* anyseq *) reg [AW-1:0]     s_araddr;
  (* anyseq *) reg [2:0]        s_arprot;
  (* anyseq *) reg              s_rready;
  (* anyseq *) reg              s_awvalid;
  (* anyseq *) reg [IW-1:0]     s_awid;
  (* anyseq *) reg [AW-1:0]     s_awaddr;
  (* anyseq *) reg [2:0]        s_awprot;
  (* anyseq *) reg              s_wvalid;
  (* anyseq *) reg              s_wlast;
  (* anyseq *) reg              s_bready;
  (* anyseq *) reg              m_arready;
  (* anyseq *) reg              m_rvalid;
  (* anyseq *) reg [IW-1:0]     m_rid;
  (* anyseq *) reg [DW-1:0]     m_rdata;
  (* anyseq *) reg              m_awready;
  (* anyseq *) reg              m_wready_unused;
  (* anyseq *) reg              m_bvalid;
  (* anyseq *) reg [IW-1:0]     m_bid;
  (* anyseq *) reg              log_rd_en;

  wire               s_arready, s_awready, s_wready;
  wire               m_arvalid, m_awvalid, m_wvalid_u;
  wire               s_rvalid, s_bvalid, m_rready, m_bready;
  wire [1:0]         s_rresp, s_bresp;
  wire [IW-1:0]      s_rid, s_bid;
  wire [DW-1:0]      s_rdata;
  wire               s_rlast;
  wire               irq, log_ovf, log_rd_valid;
  wire [47:0]        log_rd_data;
  wire               dbg_rd_pend;
  wire [1:0]         dbg_ws_state;
  wire [2:0]         dbg_log_cnt;
  wire [5:0]         dbg_taint;
  wire [IW-1:0]      dbg_rd_id, dbg_w_id;
  wire [7:0]         dbg_ts;

  tz_firewall #(
    .N_REGIONS(NR), .ADDR_WIDTH(AW), .DATA_WIDTH(DW), .ID_WIDTH(IW),
    .LOG_DEPTH(DEPTH), .TS_WIDTH(8), .TAINT_EN(1)
  ) dut (
    .ACLK(clk), .ARESETn(rstn),
    .cfg_enable(cfg_enable), .cfg_base(cfg_base),
    .cfg_mask(cfg_mask), .cfg_perm(cfg_perm),
    .cfg_int_en(int_en), .cfg_clr_ovf(1'b0),
    .log_rd_en(log_rd_en), .log_rd_data(log_rd_data),
    .log_rd_valid(log_rd_valid), .log_ovf(log_ovf), .irq(irq),
    .s_arid(s_arid), .s_araddr(s_araddr), .s_arlen(8'h0), .s_arsize(3'd2),
    .s_arburst(2'd1), .s_arprot(s_arprot), .s_arvalid(s_arvalid), .s_arready(s_arready),
    .s_rid(s_rid), .s_rdata(s_rdata), .s_rresp(s_rresp), .s_rlast(s_rlast),
    .s_rvalid(s_rvalid), .s_rready(s_rready),
    .s_awid(s_awid), .s_awaddr(s_awaddr), .s_awlen(8'h0), .s_awsize(3'd2),
    .s_awburst(2'd1), .s_awprot(s_awprot), .s_awvalid(s_awvalid), .s_awready(s_awready),
    .s_wdata(32'h0), .s_wstrb(4'hF), .s_wlast(s_wlast),
    .s_wvalid(s_wvalid), .s_wready(s_wready),
    .s_bid(s_bid), .s_bresp(s_bresp), .s_bvalid(s_bvalid), .s_bready(s_bready),
    .m_arid(), .m_araddr(), .m_arlen(), .m_arsize(), .m_arburst(),
    .m_arprot(), .m_arvalid(m_arvalid), .m_arready(m_arready),
    .m_rid(m_rid), .m_rdata(m_rdata), .m_rresp(2'b00), .m_rlast(1'b1),
    .m_rvalid(m_rvalid), .m_rready(m_rready),
    .m_awid(), .m_awaddr(), .m_awlen(), .m_awsize(), .m_awburst(),
    .m_awprot(), .m_awvalid(m_awvalid), .m_awready(m_awready),
    .m_wdata(), .m_wstrb(), .m_wlast(),
    .m_wvalid(m_wvalid_u), .m_wready(m_wready_unused),
    .m_bid(m_bid), .m_bresp(2'b00), .m_bvalid(m_bvalid), .m_bready(m_bready),
    .dbg_rd_pend(dbg_rd_pend), .dbg_ws_state(dbg_ws_state),
    .dbg_log_cnt(dbg_log_cnt), .dbg_taint(dbg_taint),
    .dbg_rd_id(dbg_rd_id), .dbg_w_id(dbg_w_id), .dbg_ts(dbg_ts));

  // ---- reset run-up ----
  reg runup = 1'b0;
  always @(posedge clk) runup <= 1'b1;
  wire rstn = runup;

  // ============ INDEPENDENT REFERENCE DECISION ============
  // Written deliberately differently from rtl/tzf_policy.sv:
  // ascending scan + found-flag; direct perm-bit indexing pv[{ns,op}].
  function ref_grant(input [NR*6-1:0] p,
                     input [NR*AW-1:0] b, input [NR*AW-1:0] mk,
                     input [NR-1:0] en,
                     input [AW-1:0] a, input [2:0] pr, input w);
    integer k;
    reg found, gbit;
    reg [5:0] pv;
    begin
      found = 1'b0; gbit = 1'b0; pv = 6'b000000;
      for (k = 0; k < NR; k = k + 1)
        if (!found && en[k] &&
            ((a & mk[k*AW +: AW]) == b[k*AW +: AW])) begin
          found = 1'b1;
          pv    = p[k*6 +: 6];
        end
      if (found) begin
        if (!pr[1]) begin                       // secure half {sx,sw,sr}
          if (w)       gbit = pv[4];
          else if (pr[2]) gbit = pv[5];
          else            gbit = pv[3];
        end else begin                          // non-secure half {nx,nw,nr}
          if (w)       gbit = pv[1];
          else if (pr[2]) gbit = pv[2];
          else            gbit = pv[0];
        end
      end
      ref_grant = gbit;
    end
  endfunction

  wire rd_ref = ref_grant(cfg_perm, cfg_base, cfg_mask, cfg_enable,
                          s_araddr, s_arprot, 1'b0);
  wire wr_ref = ref_grant(cfg_perm, cfg_base, cfg_mask, cfg_enable,
                          s_awaddr, s_awprot, 1'b1);

  wire ar_fire_obs = s_arvalid && s_arready;
  wire aw_fire_obs = s_awvalid && s_awready;
  wire blk_obs     = (ar_fire_obs && !rd_ref) || (aw_fire_obs && !wr_ref);

  // ============ SHADOW TRACKERS ============
  // write-FSM mirror (observables only)
  localparam [1:0] WS_IDLE=2'd0, WS_PASS=2'd1, WS_DRAIN=2'd2, WS_BERR=2'd3;
  reg [1:0] ws_sh = WS_IDLE;
  always @(posedge clk) if (rstn) begin
    case (ws_sh)
      WS_IDLE:  if (aw_fire_obs) ws_sh <= wr_ref ? WS_PASS : WS_DRAIN;
      WS_PASS:  if (m_bvalid && s_bready) ws_sh <= WS_IDLE;
      WS_DRAIN: if (s_wvalid && s_wlast) ws_sh <= WS_BERR;
      WS_BERR:  if (s_bready) ws_sh <= WS_IDLE;
      default:  ws_sh <= WS_IDLE;
    endcase
  end

  // blocked-READ-request RID capture mirror (rd_id_q is read-path only)
  reg [IW-1:0] rid_sh;
  always @(posedge clk) if (rstn) begin
    if (ar_fire_obs && !rd_ref)
      rid_sh <= s_arid;
  end

  // ================= INVARIANTS =================
  integer seen = 0;
  reg [2:0] pcnt; reg pseen_ts = 1'b0; reg [7:0] pts;
  reg blk_q = 1'b0; reg en_q = 1'b0;
  always @(posedge clk) if (rstn) begin
    // --- CM1/CM2..CM7: mediation & response shape ---
    assert (!(m_arvalid && !rd_ref));
    assert (!(dbg_rd_pend && !s_rvalid));
    assert (!(dbg_rd_pend && (s_rresp != 2'b11)));
    assert (!(dbg_rd_pend && !s_rlast));
    assert (!(dbg_rd_pend && (s_rdata != {DW{1'b0}})));
    assert (!(dbg_rd_pend && m_arvalid));
    assert (!(s_rvalid && !dbg_rd_pend && !m_rvalid));
    assert (!(m_awvalid && !wr_ref));
    assert (!((dbg_ws_state == WS_BERR) && (!s_bvalid || (s_bresp != 2'b11))));
    assert (! (~|cfg_enable && (m_arvalid || m_awvalid)));
    // --- CM-A: RID integrity on internal DECERR beats ---
    assert (!(dbg_rd_pend && (s_rid != rid_sh)));
    // --- CM-B: AW handshakes only in IDLE window ---
    assert (!(aw_fire_obs && (dbg_ws_state != WS_IDLE)));
    // --- CM-H: at most ONE outstanding blocked read (pend-stall enforced) ---
    assert (!(dbg_rd_pend && ar_fire_obs && !rd_ref));
    // --- CM-C: shadow FSM equals DUT write FSM ---
    assert (ws_sh == dbg_ws_state);
    // --- CM-E: irq equation (masking honored) ---
    assert (irq === (int_en && ((dbg_log_cnt != 0) || log_ovf)));
    // --- CM-F: fault-log delta invariant ---
    if (seen >= 2) begin
      // C(n) == C(n-1) + push(n-1) - pop(n-1); events pipelined one cycle
      assert (dbg_log_cnt ==
        pcnt + ((blk_q && (pcnt < DEPTH)) ? 3'd1 : 3'd0)
             - (((pcnt != 0) && en_q) ? 3'd1 : 3'd0));
    end
    // --- CM-G: timestamp free-runs (+1 every cycle) ---
    if (pseen_ts) assert (dbg_ts == pts + 8'd1);
    // --- bookkeeping for next cycle ---
    seen      = seen + 1;
    pcnt      <= dbg_log_cnt;
    blk_q     <= blk_obs;
    en_q      <= log_rd_en;
    pts       <= dbg_ts;
    pseen_ts  = 1'b1;
  end
endmodule
`default_nettype wire



