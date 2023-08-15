<?php
	if(isset($_POST["email"]) && isset($_POST["username"]) && isset($_POST["password1"]) && isset($_POST["password2"])){
		$errors = array();
		
		$emailMaxLength = 254;
		$usernameMaxLength = 20;
		$usernameMinLength = 3;
		$passwordMaxLength = 19;
		$passwordMinLength = 5;

		$sql = "SELECT username, email FROM sc_users WHERE email = ? OR username = ? LIMIT 1" ;
		
		$email = strtolower($_POST["email"]);
		$username = $_POST["username"];
		$password1 = $_POST["password1"];
		$password2 = $_POST["password2"];
		
		//信箱不符合
		if(preg_match('/\s/', $email)){
			$errors[] = "帳號不可有空格";
		}else{
			if(!validate_email_address($email)){
				$errors[] = "未知的帳號形式";
			}else{
				if(strlen($email) > $emailMaxLength){
					$errors[] = "帳號輸入太長，必須在 " . strval($emailMaxLength) . " 個字以內";
				}
			}
		}
		
		//名稱不符合
		if(strlen($username) > $usernameMaxLength || strlen($username) < $usernameMinLength){
			$errors[] = "輸入名稱錯誤，必須介於 " . strval($usernameMinLength) . " 與 " . strval($usernameMaxLength) . " 個字之間";
		}else{
			if(!ctype_alnum ($username)){
				$errors[] = "名稱必須是羅馬數字和英文字母組合";
			}
		}
		
		//密碼不符合
		if($password1 != $password2){
			$errors[] = "與驗證密碼不匹配";
		}else{
			if(preg_match('/\s/', $password1)){
				$errors[] = "密碼不可有空格";
			}else{
				if(strlen($password1) > $passwordMaxLength || strlen($password1) < $passwordMinLength){
					$errors[] = "密碼長度錯誤，必須介於 " . strval($passwordMinLength) . " 與 " . strval($passwordMaxLength) . " 個字之間";
				}else{
					if(!preg_match('/[A-Za-z]/', $password1) || !preg_match('/[0-9]/', $password1)){
						$errors[] = "密碼必須包含 1個羅馬數字 或 1個英文字母";
					}
				}
			}
		}
		
		//確認有沒有已被註冊的信箱或名稱
		if(count($errors) == 0){
			
			//確認沒有錯誤就進入到查找的部分
			require dirname(__FILE__) . '/database.php';
			
			//$sql 在最上面有定義
			if ($stmt = $mysqli_conection->prepare($sql)) {
				
				//使用兩個s就代表後兩個object都會是字串的形式
				$stmt->bind_param('ss', $email, $username);
					
				//開始執行
				if($stmt->execute()){
					
					//儲存結果
					$stmt->store_result();

					if($stmt->num_rows > 0){
					
						/* bind result variables */
						$stmt->bind_result($username_tmp, $email_tmp);

						/* fetch value */
						$stmt->fetch();
						
						if($email_tmp == $email){
							$errors[] = "信箱已被註冊";
						}
						else if($username_tmp == $username){
							$errors[] = "名稱已被註冊";
						}
					}
					
					/* close statement */
					$stmt->close();
					
				}else{
					$errors[] = "Something went wrong, please try again.";
				}
			}else{
				$errors[] = "Something went wrong, please try again.";
			}
		}
		
		//註冊最後步驟
		if(count($errors) == 0){
			
			//以下這個步驟透過將post 的密碼使用hash轉換成看不懂的樣子
			$hashedPassword = password_hash($password1, PASSWORD_BCRYPT);

			if ($stmt = $mysqli_conection->prepare("INSERT INTO sc_users (username, email, password) VALUES(?, ?, ?)")) {
				
				/* bind parameters for markers */
				$stmt->bind_param('sss', $username, $email, $hashedPassword);
					
				/* execute query */
				if($stmt->execute()){
					
					/* close statement */
					$stmt->close();
					
				}else{
					$errors[] = "Something went wrong, please try again.";
				}
			}else{
				$errors[] = "Something went wrong, please try again.";
			}
		}
		
		if(count($errors) > 0){
			echo $errors[0];
		}else{
			echo "Success";
		}
	}else{
		echo "Missing data";
	}
	
	function validate_email_address($email) {
		return preg_match('/^([a-z0-9!#$%&\'*+-\/=?^_`{|}~.]+@[a-z0-9.-]+\.[a-z0-9]+)$/i', $email);
	}
?>