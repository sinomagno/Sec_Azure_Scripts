#Get subscription list 
$SubList = gc "C:\Users\Sino\SubList.txt"

Foreach ($sub in $SubList){
    
    #For each subscription in $sub get the ID
    $SubId = Get-AzSubscription -SubscriptionName $sub -InformationAction SilentlyContinue

    #Change the subscription 
    Set-AzContext -SubscriptionId $SubId -InformationAction SilentlyContinue

    #Get WAF policy
    $AppGW = Get-AzApplicationGateway -InformationAction SilentlyContinue

    #Get RG for the Application Gateway
    $RG = $AppGW.ResourceGroupName

    #Ge tDNS Zone for the subscription
    $GetDNSName = (Get-AzDNSZone -InformationAction SilentlyContinue).Name

    #Get Name for the WAF Policy
    $wafId = $AppGW.FirewallPolicyText
    $WAFName = $wafId.Substring($wafId.LastIndexOf('/')+1).Split('"')[0]

    #Read JSON file to get the rule
    $rule_in_file = ((gc "C:\Users\Sino\test_rule.txt") | Convertfrom-Json)

    #Retrieve Name, Priority, rule type and action from the JSON file
    $rule_name = $rule_in_file.Name
    $rule_prio = $rule_in_file.Priority
    $rule_type = $rule_in_file.RuleType
    $rule_action = $rule_in_file.Action
    
    $i = 0 

    #If there is more than one condition in the rule this Do - While statement will read it and create the custom rule with the multiple conditions
    do {
        #RemoteAddr, RequestMethod, QueryString, PostArgs, RequestUri, RequestHeaders, RequestBody, RequestCookies
        $Variable_Name = $rule_in_file.MatchConditionsText[$i].MatchVariables.VariableName
        
        #Find if the selector field exist inside the JSON file
        if ($rule_in_file.MatchConditionsText[$i].MatchVariables.Selector){
            $variable = New-AzApplicationGatewayFirewallMatchVariable -VariableName $Variable_Name -Selector $rule_in_file.MatchConditionsText[$i].MatchVariables.Selector
        }
        else{
            $variable = New-AzApplicationGatewayFirewallMatchVariable -VariableName $Variable_Name
        }
        #Operator IPMatch, Equal, Contains, LessThan, GreaterThan, LessThanOrEqual, GreaterThanOrEqual, BeginsWith, EndsWith, Regex
        $operator = $rule_in_file.MatchConditionsText[$i].OperatorProperty
        
        $NegationCondition = $rule_in_file.MatchConditionsText[$i].NegationConditon
        $MatchValue = $Variable_Name = $rule_in_file.MatchConditionsText[$i].MatchValues

        #Lowercase, Trim, UrlDecode, UrlEncode, RemoveNulls, HtmlEntityDecode
        $Transform = $Variable_Name = $rule_in_file.MatchConditionsText[$i].Transforms

        #Create Web Application firewall condition
        $condition = New-AzApplicationGatewayFirewallCondition -MatchVariable $variable -Operator $operator -MatchValue $MatchValue -Transform $Transform -NegationCondition $NegationCondition

        if ($i -eq 0 ){
            $rule = New-AzApplicationGatewayFirewallCustomRule -Name $rule_name -Priority $rule_prio -RuleType $rule_type -MatchCondition $condition -Action $rule_action
        }
        else{
            $rule.MatchConditions.Add($condition)
        }

        echo $rule
        $i++
    } while($i -lt $rule_in_file.MatchConditionsText.Length)

    #get the WAF policy deployed
    $WAFPolicy = Get-AzApplicationGatewayFirewallPolicy -Name $WAFNAme -ResourceGroupName $RG 

    #Adding the custonm rule to the set of rule created previously
    $WAFPolicy.CustomRules.Add($rule)

    #Saving changing into the WAF policy
    Set-AzApplicationGatewayFirewallPolicy -InputObject $WAFPolicy 
}
