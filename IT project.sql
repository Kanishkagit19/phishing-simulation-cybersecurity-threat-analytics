CREATE DATABASE phishing_project;
USE phishing_project;
SHOW TABLES;
select * from phishing_project.deptlocationmonthlymetrics;
select * from phishing_project.deviceinventory;
select * from phishing_project.emailtrafficlog;
select * from phishing_project.employees;
select * from phishing_project.helpdesktickets;
select * from phishing_project.incidentreports;
select * from phishing_project.locationaccesslog;
select * from phishing_project.loginactivitylog;
select * from phishing_project.phishingcampaigns;
select * from phishing_project.phishingtemplates;
select * from phishing_project.roleassignmenthistory;
select * from phishing_project.securityawarenessscores;
select * from phishing_project.simulationresults;
select * from phishing_project.trainingrecords;
select * from phishing_project.vulnerabilitydata;
-- 4. Phishing Campaign Summary
-- Calculate the total number of phishing campaigns, identify the most frequently used campaign types, and find the campaign with the highest number of simulations.
select p.CampaignID,count(s.ResultID) Total_Simulations
from phishingcampaigns p
join simulationresults s
on  p.CampaignID = s.CampaignID
group by p.CampaignID
order by Total_Simulations desc;
-- 5. Phishing Campaign Type Analysis
-- Calculate the total number of phishing simulations for each campaign type and identify the most frequently used campaign types.
select p.CampaignType,(s.ResultID) as Total_Simulations
from phishingcampaigns p
join simulationresults s
on p.CampaignID = s.CampaignID
group by p.CampaignType
order by Total_Simulations desc;

-- 6. Phishing Funnel Analysis
-- Analyze the funnel from emails delivered to opened, clicked, credential submitted, and reported. Calculate the percentage at each stage.
select 
    COUNT(*) AS Emails_Delivered,
    SUM(case  when EmailOpenedFlag = 'Yes' then 1 else 0 end) as Emails_Opened,
    SUM(case when LinkClickedFlag = 'Yes' then 1 else 0 end) as Links_Clicked,
    SUM(case when  CredentialsEnteredFlag = 'Yes' then 1 else 0 end) as Credentials_Submitted,
    SUM(case when ReportedAsPhishingFlag = 'Yes' then 1 else 0 end) as  Emails_Reported
from simulationresults;

-- 7. Risk Score Ranking
-- Rank phishing simulation results based on their risk score, with the highest risk score receiving the highest priority.
select  ResultID,RiskScore,RANK() OVER (ORDER BY RiskScore DESC) AS Risk_Rank
from simulationresults
order by Risk_Rank limit 5;

-- 8. Job Role Risk Ranking
-- Rank job roles based on their average phishing RiskScore and identify the Top 10 highest-risk job roles.
select
    r.roletitle,
    count(s.resultid) as total_simulations,
    round(avg(s.riskscore)) as average_riskscore,
    rank() over(order by avg(s.riskscore) desc) as risk_rank
from roleassignmenthistory r
join simulationresults s
    on r.employeeid = s.employeeid
group by r.roletitle
order by risk_rank
limit 10;

-- 9. Campaign Difficulty Analysis — Easy Version
-- Find the total number of phishing simulations for each campaign difficulty level (Easy, Medium, Hard). 
-- Identify which difficulty level has the highest number of simulations.
select p.difficultylevel,count(s.resultid) as total_simulations
from phishingcampaigns p
join simulationresults s
on p.campaignid = s.campaignid
group by p.difficultylevel
order by total_simulations desc;

-- 10. Attack Vector Analysis
-- Analyze phishing results by attack vector and phishing template. 
-- Identify the attack types that are most successful.
select
    p.attackvector,
    count(s.resultid) as total_simulations,
    sum(case when s.linkclickedflag = 'Yes' then 1 else 0 end) as links_clicked,
    sum(case when s.credentialsenteredflag = 'Yes' then 1 else 0 end) as credentials_entered
from phishingtemplates p
join simulationresults s
    on p.templateid = s.templateid
group by p.attackvector
order by links_clicked desc;

-- 11. Training Effectiveness Analysis
-- Compare phishing click and credential submission rates between trained and untrained employees. Determine whether training is associated with better performance.
select t.completionstatus,count(s.resultid) as total_simulations,
sum(case when s.linkclickedflag = 'Yes' then 1 else 0 end) as links_clicked,
sum(case when s.credentialsenteredflag = 'Yes' then 1 else 0 end) as credentials_entered
from trainingrecords t
join simulationresults s
    on t.employeeid = s.employeeid
group by t.completionstatus;

-- 12. Repeat Offender Analysis
-- Identify employees who repeatedly clicked phishing links or submitted credentials. 
-- Rank employees based on the number of risky simulation actions.
select employeeid,
sum(case when linkclickedflag = 'Yes' or credentialsenteredflag = 'Yes'then 1 else 0 end) as risky_actions,
rank() over (order by sum(case when linkclickedflag = 'Yes' or credentialsenteredflag = 'Yes'then 1 else 0 end) desc) as risk_rank
from simulationresults
group by employeeid
having risky_actions > 1
order by risk_rank;

-- 13. Security Awareness Analysis
--  Join simulation results with security awareness scores. Compare phishing susceptibility scores with actual phishing behavior.
select s.employeeid,a.phishingsusceptibilityindex,sum(case when s.linkclickedflag = 'Yes' then 1 else 0 end) as links_clicked,
sum(case when s.credentialsenteredflag = 'Yes' then 1 else 0 end) as credentials_entered
from securityawarenessscores a
join simulationresults s
    on a.employeeid = s.employeeid
group by s.employeeid, a.phishingsusceptibilityindex
order by a.phishingsusceptibilityindex desc;

-- Task 14 – Cybersecurity Risk Scorecard
-- Calculate the average RiskScore for each employee and classify employees as High, Medium, or Low Risk.
select employeeid,round(avg(riskscore), 2) as average_risk_score,
case
        when avg(riskscore) >= 70 then 'High Risk'
        when avg(riskscore) >= 40 then 'Medium Risk'
        else 'Low Risk'
    end as risk_category
from simulationresults
group by employeeid
order by average_risk_score desc;


create view phishing_powerbi_view as
select
    s.employeeid,
    r.roletitle as role,
    p.campaigntype as campaign,
    sum(s.linkclickedflag = 'Yes') / count(*) * 100 as click_rate,
    sum(s.credentialsenteredflag = 'Yes') / count(*) * 100 as credential_rate,
    sum(s.reportedasphishingflag = 'Yes') / count(*) * 100 as report_rate,
    round(avg(s.riskscore), 2) as risk_score,
    t.completionstatus as training_status
from simulationresults s
join roleassignmenthistory r
    on s.employeeid = r.employeeid
join phishingcampaigns p
    on s.campaignid = p.campaignid
left join trainingrecords t
    on s.employeeid = t.employeeid
group by
    s.employeeid,
    r.roletitle,
    p.campaigntype,
    t.completionstatus;
    
  select * from phishing_powerbi_view;  
  show full tables;