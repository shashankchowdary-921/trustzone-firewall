// tb_firewall.sv — AXI-level directed self-checking TB (MICROSPEC v1.1)
`timescale 1ns/1ps
module tb_firewall;
  localparam int AW=32, DW=32, IW=4;
  reg ACLK=0, ARESETn=0;
  always #5 ACLK = ~ACLK;

  // ---- DUT ----
  reg  [15:0]        en; reg [16*AW-1:0] base, mask; reg [16*6-1:0] perm;
  reg                int_en, clr_ovf;
  wire               irq, log_ovf, log_rd_valid;
  reg                log_rd_en;
  wire [71:0]        log_rd_data;

  reg          s_arvalid; wire s_arready;
  reg  [IW-1:0] s_arid; reg [AW-1:0] s_araddr; reg [2:0] s_arprot;
  wire [IW-1:0] s_rid; wire [DW-1:0] s_rdata; wire [1:0] s_rresp;
  wire s_rlast, s_rvalid; reg s_rready = 1'b1;
  reg          s_awvalid; wire s_awready;
  reg  [IW-1:0] s_awid; reg [AW-1:0] s_awaddr; reg [2:0] s_awprot; reg [7:0] s_awlen;
  reg  [DW-1:0] s_wdata; reg [DW/8-1:0] s_wstrb; reg s_wlast, s_wvalid; wire s_wready;
  wire [IW-1:0] s_bid; wire [1:0] s_bresp; wire s_bvalid; reg s_bready = 1'b1;

  wire          m_arvalid; reg m_arready = 1'b1;
  wire [IW-1:0] m_arid; wire [AW-1:0] m_araddr; wire [2:0] m_arprot;
  wire [7:0] m_arlen;
  reg           m_rvalid = 1'b0; reg [IW-1:0] m_rid; reg [DW-1:0] m_rdata;
  wire          m_awvalid; reg m_awready = 1'b1; reg m_wready = 1'b1;
  wire [IW-1:0] m_awid; wire [AW-1:0] m_awaddr; wire [7:0] m_awlen;
  wire          m_wvalid;
  wire [DW-1:0] m_wdata; wire [DW/8-1:0] m_wstrb; wire m_wlast;
  reg           m_bvalid = 1'b0; reg [IW-1:0] m_bid; wire m_bready;

  integer m_ar_seen = 0;   // egress AR counter
  integer m_aw_seen = 0;

  tz_firewall #(.N_REGIONS(16)) dut (
    .ACLK(ACLK), .ARESETn(ARESETn),
    .cfg_enable(en), .cfg_base(base), .cfg_mask(mask), .cfg_perm(perm),
    .cfg_int_en(int_en), .cfg_clr_ovf(clr_ovf),
    .log_rd_en(log_rd_en), .log_rd_data(log_rd_data),
    .log_rd_valid(log_rd_valid), .log_ovf(log_ovf), .irq(irq),
    .s_arid(s_arid), .s_araddr(s_araddr), .s_arlen(8'h0), .s_arsize(3'd2),
    .s_arburst(2'd1), .s_arprot(s_arprot), .s_arvalid(s_arvalid), .s_arready(s_arready),
    .s_rid(s_rid), .s_rdata(s_rdata), .s_rresp(s_rresp), .s_rlast(s_rlast),
    .s_rvalid(s_rvalid), .s_rready(s_rready),
    .s_awid(s_awid), .s_awaddr(s_awaddr), .s_awlen(s_awlen), .s_awsize(3'd2),
    .s_awburst(2'd1), .s_awprot(s_awprot), .s_awvalid(s_awvalid), .s_awready(s_awready),
    .s_wdata(s_wdata), .s_wstrb(s_wstrb), .s_wlast(s_wlast),
    .s_wvalid(s_wvalid), .s_wready(s_wready),
    .s_bid(s_bid), .s_bresp(s_bresp), .s_bvalid(s_bvalid), .s_bready(s_bready),
    .m_arid(m_arid), .m_araddr(m_araddr), .m_arlen(m_arlen), .m_arsize(), .m_arburst(),
    .m_arprot(m_arprot), .m_arvalid(m_arvalid), .m_arready(m_arready),
    .m_rid(m_rid), .m_rdata(m_rdata), .m_rresp(2'b00), .m_rlast(1'b1),
    .m_rvalid(m_rvalid), .m_rready(),
    .m_awid(m_awid), .m_awaddr(m_awaddr), .m_awlen(m_awlen), .m_awsize(), .m_awburst(),
    .m_awprot(m_awprot), .m_awvalid(m_awvalid), .m_awready(m_awready),
    .m_wdata(m_wdata), .m_wstrb(m_wstrb), .m_wlast(m_wlast),
    .m_wvalid(m_wvalid), .m_wready(m_wready),
    .m_bid(m_bid), .m_bresp(2'b00), .m_bvalid(m_bvalid), .m_bready(m_bready));

  // ---- stub subordinate responses (1-cycle-delayed) ----
  reg ar_d, aw_w_d;
  always @(posedge ACLK or negedge ARESETn) begin
    if (!ARESETn) begin ar_d<=0; aw_w_d<=0; m_rvalid<=0; m_bvalid<=0; end
    else begin
      if (m_arvalid && m_arready) begin ar_d<=1; m_rid<=m_arid; m_rdata<=32'hFACE_CAFE; end
      else begin ar_d<=0; end
      m_rvalid <= ar_d;
      if (m_awvalid && m_awready) m_aw_seen = m_aw_seen + 1;
      if (m_arvalid && m_arready) m_ar_seen = m_ar_seen + 1;
      // B for granted writes: fire when w beat passed in PASS mode
      if (m_wvalid && m_wready && m_wlast) begin aw_w_d<=1; m_bid<=m_awid; end
      else aw_w_d <= 0;
      m_bvalid <= aw_w_d;
    end
  end

  integer errs = 0;
  task chk(input string name, input logic cond);
    if (!cond) begin $display("FAIL %s @%0t", name, $time); errs=errs+1; end
    else $display("pass %s", name);
  endtask

  task cfg_region(input int i, input [AW-1:0] b, input [AW-1:0] mk,
                  input [5:0] p, input logic e);
    en[i]=e; base[i*AW+:AW]=b; mask[i*AW+:AW]=mk; perm[i*6+:6]=p;
  endtask

  // returns observed resp; also checks egress mediation
  task rd_txn(input [AW-1:0] a, input [2:0] pr,
              input logic exp_g, input [3:0] exp_reg);
    int seen_egress; logic [1:0] resp; int guard;
    seen_egress = m_ar_seen;
    @(negedge ACLK);
    s_arid=4'hA; s_araddr=a; s_arprot=pr; s_arvalid=1;
    #1; // settle combinational decision path
    if (exp_g) chk("rd_zero_cycle_egress", m_arvalid === 1'b1);
    @(posedge ACLK);
    while (!s_arready) @(posedge ACLK);
    s_arvalid = 0;
    // collect response
    guard = 0; resp = 2'bx;
    while (!s_rvalid && guard < 20) begin @(posedge ACLK); guard=guard+1; end
    resp = s_rresp; @(posedge ACLK);
    chk("rd_timeout", guard < 20);
    if (exp_g) begin
      chk("rd_resp_okay", resp == 2'b00);
      chk("rd_egress_happened", m_ar_seen == seen_egress + 1);
    end else begin
      chk("rd_resp_decerr", resp == 2'b11);
      chk("rd_no_egress", m_ar_seen == seen_egress);
    end
  endtask

  task wr_txn(input [AW-1:0] a, input [2:0] pr, input [7:0] len,
              input logic exp_g, input logic [3:0] exp_reg);
    int i_, seen_aw, guard; logic [1:0] resp;
    seen_aw = m_aw_seen;
    @(negedge ACLK);
    s_awid=4'h5; s_awaddr=a; s_awprot=pr; s_awlen=len; s_awvalid=1;
    @(posedge ACLK);
    while (!s_awready) @(posedge ACLK);
    s_awvalid=0;
    // drive W beats
    for (i_=0; i_<=len; i_=i_+1) begin
      @(negedge ACLK);
      s_wvalid=1; s_wdata=i_; s_wstrb={4{1'b1}}; s_wlast=(i_==len);
      @(posedge ACLK);
      while (!s_wready) @(posedge ACLK);
    end
    @(negedge ACLK); s_wvalid=0; s_wlast=0;
    guard=0; resp=2'bx;
    while (!s_bvalid && guard<40) begin @(posedge ACLK); guard=guard+1; end
    resp=s_bresp; @(posedge ACLK);
    chk("wr_timeout", guard<40);
    if (exp_g) begin
      chk("wr_resp_okay", resp==2'b00);
      chk("wr_egress_happened", m_aw_seen==seen_aw+1);
    end else begin
      chk("wr_resp_decerr", resp==2'b11);
      chk("wr_no_egress", m_aw_seen==seen_aw);
    end
  endtask

  // log head check + pop
  task chk_log_pop(input [AW-1:0] a, input [1:0] prot21, input [1:0] op,
                   input [3:0] regn);
    @(negedge ACLK); log_rd_en=1;
    @(posedge ACLK);
    // log head check + pop; entry={ts[71:40],addr[39:8],prot[7:6],op[5:4],region[3:0]}
    chk("log_valid", log_rd_valid);
    chk("log_addr",  log_rd_data[39:8]  === a);
    chk("log_prot",  log_rd_data[7:6]   === prot21);
    chk("log_op",    log_rd_data[5:4]   === op);
    chk("log_reg",   log_rd_data[3:0]   === regn);
    @(negedge ACLK); log_rd_en=0;
  endtask

  integer k;
  initial begin
    en=0; base=0; mask=0; perm=0; int_en=0; clr_ovf=0; log_rd_en=0;
    s_arvalid=0; s_awvalid=0; s_wvalid=0; s_wlast=0;
    s_arid=0; s_araddr=0; s_arprot=0; s_awid=0; s_awaddr=0; s_awprot=0; s_awlen=0;
    repeat(4) @(negedge ACLK);
    ARESETn = 1;
    repeat(2) @(negedge ACLK);

    // T1 default-deny after reset (all regions disabled)
    int_en=1;
    rd_txn(32'hC000_1000, 3'b000, 0, 4'hF);
    chk("T1_irq", irq===1'b1);
    chk_log_pop(32'hC000_1000, 2'b00, 2'b00, 4'hF);

    // T2 secure read granted, zero-cycle egress
    cfg_region(0, 32'hC000_0000, 32'hFF00_0000, 6'b001000, 1'b1); // sr
    rd_txn(32'hC000_1234, 3'b000, 1, 4'h0);

    // T3 ns read blocked -> log prot field {inst,ns} = 2'b01
    rd_txn(32'hC000_1234, 3'b010, 0, 4'h0);
    chk_log_pop(32'hC000_1234, 2'b01, 2'b00, 4'h0);

    // T4 fetch needs X
    rd_txn(32'hC000_1234, 3'b100, 0, 4'h0);
    cfg_region(0, 32'hC000_0000, 32'hFF00_0000, 6'b101000, 1'b1); // sx|sr
    rd_txn(32'hC000_1234, 3'b100, 1, 4'h0);

    // T5 overlap lowest-index-wins at AXI level:
    // C0F0_1111 matches BOTH r0 (FF000000) and r1 (FFF00000) -> r0 wins.
    cfg_region(1, 32'hC0F0_0000, 32'hFFF0_0000, 6'b000001, 1'b1); // nr only
    rd_txn(32'hC0F0_1111, 3'b000, 1, 4'h0);   // secure read: r0 sr -> GRANT via r0
    rd_txn(32'hC0F0_1111, 3'b010, 0, 4'h0);   // ns read: r0 has no nr -> BLOCK
    en[0]=0;                                   // drop winner -> r1 takes over
    rd_txn(32'hC0F0_1111, 3'b010, 1, 4'h0);   // ns read via r1 now GRANTs

    // T6 blocked burst write drains then DECERR
    wr_txn(32'hD000_0000, 3'b000, 8'd3, 0, 4'hF);

    // T7 granted single-beat write
    cfg_region(2, 32'hD000_0000, 32'hFF00_0000, 6'b010000, 1'b1); // sw
    wr_txn(32'hD000_2000, 3'b000, 8'd0, 1, 4'h2);

    // T8 overflow: LOG_DEPTH=8; push 9 blocks
    int_en=1;
    for (k=0;k<9;k=k+1) rd_txn(32'hE000_0000 + k*'h1000, 3'b000, 0, 4'hF);
    chk("T8_ovf", log_ovf===1'b1);
    chk("T8_irq", irq===1'b1);
    // drain all 8 entries
    repeat(8) begin @(negedge ACLK); log_rd_en=1; @(posedge ACLK); @(negedge ACLK); log_rd_en=0; end
    chk("T8_empty_after_drain", log_rd_valid===1'b0);
    chk("T8_irq_sticky", irq===1'b1);         // sticky OVF keeps irq
    clr_ovf=1; @(negedge ACLK); clr_ovf=0;
    chk("T8_clr", irq===1'b0 && log_ovf===1'b0);

    if (errs==0) $display("TB_FIREWALL: ALL PASS");
    else $display("TB_FIREWALL: %0d FAILURES", errs);
    $finish;
  end

  initial begin
    #100000; $display("GLOBAL TIMEOUT"); $fatal;
  end
endmodule
