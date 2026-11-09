<?xml version="1.0" encoding="UTF-8"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
	<Header id="bay" version="1" revision="A"/>
	<Substation name="S1">
		<VoltageLevel name="V1">
			<Bay name="B1">
				<LNode iedName="Pub" ldInst="LD0" lnClass="XCBR" lnInst="1"/>
			</Bay>
		</VoltageLevel>
	</Substation>
	<Communication>
		<SubNetwork name="Bus" type="8-MMS">
			<ConnectedAP iedName="Pub" apName="AP1">
				<Address>
					<P type="IP">10.0.0.1</P>
				</Address>
				<GSE ldInst="LD0" cbName="gcb1">
					<Address>
						<P type="MAC-Address">01-0C-CD-01-00-01</P>
						<P type="APPID">0001</P>
						<P type="VLAN-ID">000</P>
						<P type="VLAN-PRIORITY">4</P>
					</Address>
				</GSE>
			</ConnectedAP>
			<ConnectedAP iedName="Sub" apName="AP1"/>
		</SubNetwork>
	</Communication>
	<IED name="Pub">
		<AccessPoint name="AP1">
			<Server>
				<Authentication/>
				<LDevice inst="LD0">
					<LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
						<DataSet name="ds1">
							<FCDA ldInst="LD0" lnClass="XCBR" lnInst="1" doName="Pos" daName="stVal" fc="ST"/>
						</DataSet>
						<ReportControl name="rcb1" datSet="ds1" confRev="1" rptID="r1">
							<TrgOps dchg="true"/>
							<OptFields seqNum="true"/>
							<RptEnabled max="1">
								<ClientLN iedName="Sub" ldInst="LD0" lnClass="IHMI" lnInst="1"/>
							</RptEnabled>
						</ReportControl>
						<GSEControl name="gcb1" datSet="ds1" appID="Pub/gcb1" confRev="1">
							<IEDName>Sub</IEDName>
						</GSEControl>
					</LN0>
					<LN lnClass="XCBR" inst="1" lnType="XCBR_T"/>
				</LDevice>
			</Server>
		</AccessPoint>
	</IED>
	<IED name="Sub">
		<AccessPoint name="AP1">
			<Server>
				<Authentication/>
				<LDevice inst="LD0">
					<LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
						<Inputs>
							<ExtRef iedName="Pub" ldInst="LD0" lnClass="XCBR" lnInst="1" doName="Pos" daName="stVal" serviceType="GOOSE" srcLDInst="LD0" srcLNClass="LLN0" srcCBName="gcb1" intAddr="in1"/>
							<ExtRef intAddr="in2"/>
						</Inputs>
					</LN0>
					<LN lnClass="LGOS" inst="1" lnType="LGOS_T">
						<DOI name="GoCBRef">
							<DAI name="setSrcRef">
								<Val>PubLD0/LLN0$GO$gcb1</Val>
							</DAI>
						</DOI>
					</LN>
					<LN lnClass="IHMI" inst="1" lnType="IHMI_T"/>
				</LDevice>
			</Server>
		</AccessPoint>
	</IED>
	<DataTypeTemplates>
		<LNodeType id="LLN0_T" lnClass="LLN0">
			<DO name="Beh" type="ENS_T"/>
		</LNodeType>
		<LNodeType id="XCBR_T" lnClass="XCBR">
			<DO name="Pos" type="DPC_T"/>
		</LNodeType>
		<LNodeType id="LGOS_T" lnClass="LGOS">
			<DO name="GoCBRef" type="ORG_T"/>
		</LNodeType>
		<LNodeType id="IHMI_T" lnClass="IHMI">
			<DO name="Beh" type="ENS_T"/>
		</LNodeType>
		<DOType id="ENS_T" cdc="ENS">
			<DA name="stVal" bType="Enum" type="Beh_E" fc="ST"/>
		</DOType>
		<DOType id="DPC_T" cdc="DPC">
			<DA name="stVal" bType="Dbpos" fc="ST" dchg="true"/>
		</DOType>
		<DOType id="ORG_T" cdc="ORG">
			<DA name="setSrcRef" bType="ObjRef" fc="SP"/>
		</DOType>
		<EnumType id="Beh_E">
			<EnumVal ord="1">on</EnumVal>
		</EnumType>
	</DataTypeTemplates>
</SCL>
