// tz_firewall.sv — AXI4 TrustZone-style firewall (MICROSP
// Granted traffic: combinational passthrough = ZERO added pipeline stages.
// Blocked traffic: bounded DECERR response, logged.
module tz_firewall #(
  parameter int N_REGIONS  = 16,
  parameter int ADDR_WIDTH = 32,
  parameter int DATA_WIDTH = 32,
  parameter int ID_WIDTH   = 4,
  parameter int LOG_DEPTH  = 8,
  parameter int TS_WIDTH   = 32,
  parameter int TAINT_EN   = 0,  localparam int PW = $clog2(N_REGIONS)
)(
  input  wire                          ACLK,
  input  wire                          ARESETn,
  // ---- config (SEC 5: direct inputs; bus wrapper deferred) ----
  input  wire [N_REGIONS-1:0]          cfg_enable,
  input  wire [N_REGIONS*ADDR_WIDTH-1:0] cfg_base,
  input  wire [N_REGIONS*ADDR_WIDTH-1:0] cfg_mask,
  input  wire [N_REGIONS*6-1:0]        cfg_perm,
  input  wire                          cfg_int_en,
  input  wire                          cfg_clr_ovf,
  // ---- log read port ----
  input  wire                          log_rd_en,
  output wire [TS_WIDTH+ADDR_WIDTH+4+PW-1:0] log_rd_data,
  output wire                          log_rd_valid,
  output wire                          log_ovf,
  output wire                          irq,
  // ---- AXI4 slave (ingress) : AR ----
  input  wire [ID_WIDTH-1:0]           s_arid,
  input  wire [ADDR_WIDTH-1:0]         s_araddr,
  input  wire [7:0]                    s_arlen,
  input  wire [2:0]                    s_arsize,
  input  wire [1:0]                    s_arburst,
  input  wire [2:0]                    s_arprot,
  input  wire                          s_arvalid,
  output wire                          s_arready,
  // R
  output wire [ID_WIDTH-1:0]           s_rid,
  output wire [DATA_WIDTH-1:0]         s_rdata,
  output wire [1:0]                    s_rresp,
  output wire                          s_rlast,
  output wire                          s_rvalid,
  input  wire                          s_rready,
  // ---- AXI4 slave (ingress) : AW/W/B ----
  input  wire [ID_WIDTH-1:0]           s_awid,
  input  wire [ADDR_WIDTH-1:0]         s_awaddr,
  input  wire [7:0]                    s_awlen,
  input  wire [2:0]                    s_awsize,
  input  wire [1:0]                    s_awburst,
  input  wire [2:0]                    s_awprot,
  input  wire                          s_awvalid,
  output wire                          s_awready,
  input  wire [DATA_WIDTH-1:0]         s_wdata,
  input  wire [DATA_WIDTH/8-1:0]       s_wstrb,
  input  wire                          s_wlast,
  input  wire                          s_wvalid,
  output wire                          s_wready,
  output wire [ID_WIDTH-1:0]           s_bid,
  output wire [1:0]                    s_bresp,
  output wire                          s_bvalid,
  input  wire                          s_bready,
  // ---- AXI4 master (egress) : AR/R ----
  output wire [ID_WIDTH-1:0]           m_arid,
  output wire [ADDR_WIDTH-1:0]         m_araddr,
  output wire [7:0]                    m_arlen,
  output wire [2:0]                    m_arsize,
  output wire [1:0]                    m_arburst,
  output wire [2:0]                    m_arprot,
  output wire                          m_arvalid,
  input  wire                          m_arready,
  input  wire [ID_WIDTH-1:0]           m_rid,
  input  wire [DATA_WIDTH-1:0]         m_rdata,
  input  wire [1:0]                    m_rresp,
  input  wire                          m_rlast,
  input  wire                          m_rvalid,
  output wire                          m_rready,
  // ---- AXI4 master (egress) : AW/W/B ----
  output wire [ID_WIDTH-1:0]           m_awid,
  output wire [ADDR_WIDTH-1:0]         m_awaddr,
  output wire [7:0]                    m_awlen,
  output wire [2:0]                    m_awsize,
  output wire [1:0]                    m_awburst,
  output wire [2:0]                    m_awprot,
  output wire                          m_awvalid,
  input  wire                          m_awready,
  output wire [DATA_WIDTH-1:0]         m_wdata,
  output wire [DATA_WIDTH/8-1:0]       m_wstrb,
  output wire                          m_wlast,
  output wire                          m_wvalid,
  input  wire                          m_wready,
  input  wire [ID_WIDTH-1:0]           m_bid,
  input  wire [1:0]                    m_bresp,
  input  wire                          m_bvalid,
  output wire                          m_bready,
  // ---- formal observation ports (proof-only, no functional load) ----
  output wire                          dbg_rd_pend,
  output wire [1:0]                    dbg_ws_state,
  output wire [( LOG_DEPTH <= 1) ? 1 : $clog2(LOG_DEPTH+1)-1:0] dbg_log_cnt,
  output wire [5:0]                    dbg_taint,
  output wire [ID_WIDTH-1:0]           dbg_rd_id,
  output wire [ID_WIDTH-1:0]           dbg_w_id,
  output wire [TS_WIDTH-1:0]           dbg_ts
);
  localparam [1:0] RESP_DECERR=2'b11;
  localparam [1:0] OP_R=2'b00, OP_W=2'b01, OP_X=2'b10;

  // ================= READ PATH (SEC 3/3.1) =================
  wire rd_grant, rd_hit_any;
  wire [PW-1:0] rd_hit_region;

  tzf_policy #(.N_REGIONS(N_REGIONS), .ADDR_WIDTH(ADDR_WIDTH)) u_pol_r (
    .cfg_enable(cfg_enable), .cfg_base(cfg_base), .cfg_mask(cfg_mask),
    .cfg_perm(cfg_perm), .addr(s_araddr), .axprot(s_arprot), .is_write(1'b0),
    .grant(rd_grant), .hit_any(rd_hit_any), .hit_region(rd_hit_region)
  );

  wire ar_fire    = s_arvalid && s_arready;
  reg             rd_pend_q;
  reg [ID_WIDTH-1:0] rd_id_q;
  assign s_arready = !rd_pend_q && (rd_grant ? m_arready : 1'b1);  assign m_arvalid = s_arvalid && rd_grant && !rd_pend_q;
  assign m_arid    = s_arid;      assign m_araddr  = s_araddr;
  assign m_arlen   = s_arlen;     assign m_arsize  = s_arsize;
  assign m_arburst = s_arburst;   assign m_arprot  = s_arprot;

  // R channel mux: granted -> mirror; blocked -> internal DECERR beat
  assign s_rvalid = rd_pend_q ? 1'b1      : m_rvalid;
  assign s_rid    = rd_pend_q ? rd_id_q   : m_rid;
  assign s_rdata  = rd_pend_q ? {DATA_WIDTH{1'b0}} : m_rdata;
  assign s_rresp  = rd_pend_q ? RESP_DECERR : m_rresp;
  assign s_rlast  = rd_pend_q ? 1'b1       : m_rlast;
  assign m_rready = rd_pend_q ? 1'b0       : s_rready;

  wire r_int_done = rd_pend_q && s_rready;
  always @(posedge ACLK or negedge ARESETn) begin
    if (!ARESETn) begin
      rd_pend_q <= 1'b0; rd_id_q <= {ID_WIDTH{1'b0}};
    end else begin
      if (ar_fire && !rd_grant) begin
        rd_pend_q <= 1'b1;
        rd_id_q   <= s_arid;
      end else if (r_int_done) begin
        rd_pend_q <= 1'b0;
      end
    end
  end

  // ================= WRITE PATH (SEC 3/3.1) =================
  localparam [1:0] WS_IDLE=2'd0, WS_PASS=2'd1, WS_DRAIN=2'd2, WS_BERR=2'd3;
  reg [1:0] ws_state;
  reg [ID_WIDTH-1:0] w_id_q;

  wire wr_grant, wr_hit_any;
  wire [PW-1:0] wr_hit_region;

  tzf_policy #(.N_REGIONS(N_REGIONS), .ADDR_WIDTH(ADDR_WIDTH)) u_pol_w (
    .cfg_enable(cfg_enable), .cfg_base(cfg_base), .cfg_mask(cfg_mask),
    .cfg_perm(cfg_perm), .addr(s_awaddr), .axprot(s_awprot), .is_write(1'b1),
    .grant(wr_grant), .hit_any(wr_hit_any), .hit_region(wr_hit_region)
  );

  wire aw_fire = s_awvalid && s_awready;

  assign s_awready = (ws_state == WS_IDLE) &&
                     (wr_grant ? m_awready : 1'b1);
  assign m_awvalid = (ws_state == WS_IDLE) && s_awvalid && wr_grant;
  assign m_awid    = s_awid;      assign m_awaddr  = s_awaddr;
  assign m_awlen   = s_awlen;     assign m_awsize  = s_awsize;
  assign m_awburst = s_awburst;   assign m_awprot  = s_awprot;

  assign s_wready = (ws_state == WS_PASS)  ? m_wready :
                    (ws_state == WS_DRAIN) ? 1'b1 : 1'b0;
  assign m_wvalid = (ws_state == WS_PASS) ? s_wvalid : 1'b0;
  assign m_wdata  = s_wdata;
  assign m_wstrb  = s_wstrb;
  assign m_wlast  = s_wlast;

  wire w_drain_done = (ws_state == WS_DRAIN) && s_wvalid && s_wlast;
  wire b_pass_fire  = (ws_state == WS_PASS) && m_bvalid && s_bready;

  assign s_bvalid = (ws_state == WS_BERR) ? 1'b1     : m_bvalid;
  assign s_bid    = (ws_state == WS_BERR) ? w_id_q   : m_bid;
  assign s_bresp  = (ws_state == WS_BERR) ? RESP_DECERR : m_bresp;
  assign m_bready = (ws_state == WS_PASS) ? s_bready : 1'b0;

  always @(posedge ACLK or negedge ARESETn) begin
    if (!ARESETn) begin
      ws_state <= WS_IDLE; w_id_q <= {ID_WIDTH{1'b0}};
    end else begin
      case (ws_state)
        WS_IDLE: if (aw_fire) begin
                   if (!wr_grant) begin
                     ws_state <= WS_DRAIN;
                     w_id_q   <= s_awid;
                   end else begin
                     ws_state <= WS_PASS;
                   end
                 end
        WS_PASS:  if (b_pass_fire) ws_state <= WS_IDLE;
        WS_DRAIN: if (w_drain_done) ws_state <= WS_BERR;
        WS_BERR:  if (s_bready) ws_state <= WS_IDLE;
        default:  ws_state <= WS_IDLE;
      endcase
    end
  end

  // ================= FAULT LOG (SEC 4) =================
  wire rd_block_ev = ar_fire && !rd_grant;
  wire wr_block_ev = aw_fire && !wr_grant;
  wire block_ev    = rd_block_ev || wr_block_ev;

  wire [( LOG_DEPTH <= 1) ? 1 : $clog2(LOG_DEPTH+1)-1:0] u_log_cnt;
  wire [TS_WIDTH-1:0]                  u_log_ts;

  wire [ADDR_WIDTH-1:0] blk_addr = wr_block_ev ? s_awaddr : s_araddr;
  /* verilator lint_off UNUSEDSIGNAL */
  // AxPROT[0] (privileged) intentionally ignored — MICROSPEC SEC 3 limitation
  wire [2:0]            blk_prot = wr_block_ev ? s_awprot : s_arprot;
  /* verilator lint_on UNUSEDSIGNAL */
  wire                  blk_wr   = wr_block_ev;
  // SEC 4: no-match blocks logged with all-ones region code
  wire [PW-1:0]         blk_reg  = wr_block_ev
      ? (wr_hit_any ? wr_hit_region : {PW{1'b1}})
      : (rd_hit_any ? rd_hit_region : {PW{1'b1}});

  wire [1:0] blk_op = blk_wr ? OP_W : (blk_prot[2] ? OP_X : OP_R);

  tzf_faultlog #(
    .LOG_DEPTH(LOG_DEPTH), .ADDR_WIDTH(ADDR_WIDTH),
    .TS_WIDTH(TS_WIDTH), .REGION_W(PW)
  ) u_log (
    .clk(ACLK), .rst_n(ARESETn),
    .push_i(block_ev), .push_addr(blk_addr),
    .push_prot(blk_prot[2:1]), .push_op(blk_op), .push_region(blk_reg),
    .rd_en(log_rd_en), .rd_data(log_rd_data),
    .rd_valid(log_rd_valid), .cnt_o(u_log_cnt), .ts_o(u_log_ts),
    .ovf_sticky(log_ovf), .ovf_clr(cfg_clr_ovf),
    .int_en(cfg_int_en), .irq(irq)
  );

  assign dbg_rd_pend  = rd_pend_q;
  assign dbg_ws_state = ws_state;
  assign dbg_log_cnt  = u_log_cnt;
  assign dbg_rd_id    = rd_id_q;
  assign dbg_w_id     = w_id_q;
  assign dbg_ts       = u_log_ts;

  generate
    if (TAINT_EN != 0) begin : GEN_TAINT
      wire act_fire   = ar_fire | aw_fire;
      wire act_ns     = aw_fire ? s_awprot[1] : s_arprot[1];
      wire [PW-1:0] act_reg = aw_fire ? wr_hit_region : rd_hit_region;
      wire        act_any  = aw_fire ? wr_hit_any    : rd_hit_any;
      tzf_taint #(.REGION_W(PW)) u_taint (
        .rd_grant(rd_grant), .wr_grant(wr_grant),
        .act_fire(ar_fire | aw_fire),
        .req_ns(act_ns),
        .hit_region(act_reg), .hit_any(act_any),
        .tnt_status(dbg_taint));
    end else begin : GEN_NO_TAINT
      assign dbg_taint = 6'b0;
    end
  endgenerate
endmodule



